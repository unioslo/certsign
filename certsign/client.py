#!/usr/bin/env python
import json, os, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen # Python 3
    from urllib.request import Request
except ImportError:
    from urllib2 import urlopen # Python 2
    from urllib2 import Request as Request_orig

    class Request(Request_orig):
        def __init__(self, *args, **kwargs):
            self._method = kwargs.pop('method', None)
            Request_orig.__init__(self, *args, **kwargs)

        def get_method(self):
            if self._method is not None:
                return self._method
            return Request_orig.get_method(self)

from . import crypto

DEFAULT_CA_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
ACME_ALG = "RS256"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def sign_csr(
    account_key,
    csr_file,
    challenge_dir,
    account_email=None,
    ca_directory=DEFAULT_CA_DIRECTORY,
    log=LOGGER,
):
    # parse account key to get public key
    log.info("Parsing account key...")
    jwk, thumbprint = generate_jwk(account_key)
    client = ACMEClient(
        ACMEClient.get_directory_index(ca_directory),
        account_key,
        jwk
    )

    log.info("Parsing CSR...")
    domains = crypto.get_csr_domains(csr_file)

    contact = []
    if account_email:
        contact.append('mailto:' + account_email)

    # get the certificate domains and expiration
    log.info("Check account...")
    account, needs_update = account_registration_handler(
        contact,
        client.send_signed_request(
            client.directory['newAccount'], {
                "termsOfServiceAgreement": True,
                "contact": contact,
            }
        )
    )
    client.use_account(account.url)
    if needs_update:
        log.info("Update contact information")
        client.send_signed_request(account.url, {"contact": account.contact})

    log.info("Create new order...")
    order = signing_order_handler(client.send_signed_request(
        client.directory['newOrder'], {
            "identifiers": [{"type": "dns", "value": d} for d in domains]
        }
    ))

    for auth_url in order.authorizations:
        authorization = generic_handler(
            client.send_signed_request(auth_url),
            "Error getting challenges"
        )
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # make the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(challenge_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url
            ))

        # notify challenge is ready
        generic_handler(
            client.send_signed_request(challenge['url'], payload={}),
            "Error submitting challenges for {0}".format(domain)
        )

        # wait for challenge to be verified
        headers, authorization = client.poll_request(
            auth_url,
            handler=poll_handler(
                ["pending"],
                "Error checking challenge status for {0}".format(domain)
            )
        )
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(
                domain, authorization))
        log.info("{0} verified!".format(domain))

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = crypto.csr_to_der_format(csr_file)
    generic_handler(client.send_signed_request(order.finalize, {
        "csr": csr_der,
    }), "Error finalizing order")

    # poll the order to monitor when it's done
    headers, body = client.poll_request(
        order.url,
        handler=poll_handler(
            ["pending", "processing"],
            "Error checking order status"
        )
    )
    if body['status'] != "valid":
        raise ValueError("Order failed: {0}".format(body))

    # get the new certificate
    cert = generic_handler(
        client.send_signed_request(body['certificate']),
        "Failed to download the certificate"
    )
    log.info("Certificate signed!")
    return cert


class ACMEClient(object):

    def __init__(self, directory, account_key, jwk):
        self.account_key = account_key
        self.jwk = jwk
        self.directory = directory
        self.account_uri = None

    def use_account(self, uri):
        self.account_uri = uri

    @staticmethod
    def get_directory_index(ca_directory_url):
        return generic_handler(
            ACMEClient.send_request(ca_directory_url),
            "Could not get directory index for {}".format(ca_directory_url)
        )

    def get_nonce(self):
        request = Request(self.directory['newNonce'], method="HEAD")
        return urlopen(request).headers['Replay-Nonce']

    @staticmethod
    def send_request(url, data=None):
        try:
            request = Request(
                url,
                data=data.encode('utf8') if data is not None else None,
                headers={
                    'Content-Type': 'application/jose+json',
                    'User-Agent': 'certsign',
                },
            )
            resp = urlopen(request)
            headers = dict(status=resp.code)
            headers.update(to_lower_case_keys(resp.info()))
            body = resp.read()
        except IOError as e:
            headers = dict(status=getattr(e, "code", None))
            if hasattr(e, "info"):
                headers.update(to_lower_case_keys(e.info()))
            body = e.read() if hasattr(e, "read") else str(e)

        content_type = headers.get('content-type')
        if content_type == "application/json":
            body = json.loads(body.decode('utf8'))
        return headers, body

    def send_signed_request(self, url, payload=None):
        data = json.dumps(
            self.signed_json_payload(url, payload, self.get_nonce())
        )
        return self.send_request(url, data)

    def signed_json_payload(self, url, payload, nonce):
        payload64 = crypto.nopad_b64(json.dumps(payload)) \
            if payload is not None else ""
        protected = {"url": url, "alg": ACME_ALG, "nonce": nonce}
        if self.account_uri is None:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.account_uri
        protected64 = crypto.nopad_b64(json.dumps(protected))
        signature = crypto.digest_sign(self.account_key, "{0}.{1}".format(
            protected64, payload64))
        return {
            "protected": protected64,
            "payload": payload64,
            "signature": signature,
        }

    def poll_request(self, url, handler):
        while True:
            response = self.send_signed_request(url)
            complete = handler(response)
            if not complete:
                time.sleep(2)
                continue
            return response


class Account(object):
    def __init__(self, url, contact):
        self.url = url
        self.contact = contact


class Order(object):
    def __init__(self, url, authorizations, finalize):
        self.url = url
        self.authorizations = authorizations
        self.finalize = finalize


def account_registration_handler(contact, response):
    headers, body = response

    status = headers['status']
    do_update = False
    if status in [200, 201]:
        account = Account(headers['location'], contact)
        if status == 200:
            do_update = 'contact' in body and contact != body['contact']
    else:
        raise ValueError("Error registering: {0} {1}".format(status, body))

    return account, do_update


def signing_order_handler(response):
    headers, body = response
    status = headers['status']
    if status != 201:
        raise ValueError(
            "Error creating new signing order: {0} {1}".format(status, body))

    return Order(headers['location'], body["authorizations"], body["finalize"])


def new_certificate_handler(response):
    headers, body = response
    status = headers['status']
    if status != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(status, body))

    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(body).decode('utf8'), 64))
    )


def generic_handler(response, error_message):
    headers, body = response
    status = headers['status']
    if status < 200 or status >= 300:
        raise ValueError("{0}: {1} {2}".format(error_message, status, body))
    return body


def poll_handler(pending_statuses, error_message):
    def _handler(response):
        body = generic_handler(response, error_message)
        return not (body['status'] in pending_statuses)
    return _handler


def generate_jwk(account_key):
    pub_hex, pub_exp = crypto.get_rsa_key_public_info(account_key)
    jwk = {
        "e": crypto.nopad_b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": crypto.nopad_b64(
            binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = crypto.nopad_b64(hashlib.sha256(
        accountkey_json.encode('utf8')).digest())
    return jwk, thumbprint


def to_lower_case_keys(mapping):
    lcase = {}
    for key, value in mapping.items():
        if hasattr(key, 'lower'):
            key = key.lower()
        lcase[key] = value
    return lcase
