#!/usr/bin/env python
import json, os, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

from . import crypto

DEFAULT_CA_DIRECTORY = "https://acme-v01.api.letsencrypt.org"


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
    header, thumbprint = generate_header(account_key)
    client = ACMEClient(ca_directory, account_key, header)

    log.info("Parsing CSR...")
    domains = crypto.get_csr_domains(csr_file)

    contact = []
    if account_email:
        contact.append('mailto:' + account_email)

    # get the certificate domains and expiration
    log.info("Check account...")
    created, account_uri = account_registration_handler(client.send_signed_request(
        client.ca_directory + "/acme/new-reg", {
            "resource": "new-reg",
            "agreement": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
            "contact": contact
        }
    ))
    if created:
        log.info("New registration")
    else:
        account, needs_update = account_handler(
            contact, client.send_signed_request(account_uri, {'resource':'reg'})
        )
        if needs_update:
            log.info("Update contact information")
            account['contact'] = contact
            client.send_signed_request(account_uri, account)

    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        token, challenge = new_challenge_handler(
            client.send_signed_request(client.ca_directory + "/acme/new-authz", {
              "resource": "new-authz",
                "identifier": {"type": "dns", "value": domain},
            })
        )

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

        # notify challenge are met
        result, info = client.send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        status = info['status']
        if status != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(status, result))

        # wait for challenge to be verified
        while True:
            try:
                challenge_status = challenge_verification_handler(urlopen(challenge['uri']).read())
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))
                ))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("{0} verified!".format(domain))
                os.remove(wellknown_path)
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status
                ))

    # get the new certificate
    log.info("Signing certificate...")
    csr_der = crypto.csr_to_der_format(csr_file)
    cert = new_certificate_handler(client.send_signed_request(client.ca_directory + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": csr_der,
    }, binary=True))
    # return signed certificate!
    log.info("Certificate signed!")
    return cert


def account_registration_handler(response):
    result, info = response

    uri = None
    if 'location' in info:
        uri = info['location']
    status = info["status"]
    if status in [200, 201]:
        return True, uri
    elif status == 409:
        return False, uri
    else:
        raise ValueError("Error registering: {0} {1}".format(status, result))


def account_handler(contact, response):
    result, _ = response
    do_update = False
    if 'contact' in result:
        if contact != result['contact']:
            do_update = True
    elif len(contact) > 0:
        do_update = True
    return result, do_update


def new_challenge_handler(response):
    result, info = response
    status = info['status']
    if status != 201:
        raise ValueError("Error requesting challenges: {0} {1}".format(status, result))

        # make the challenge file
    challenge = [c for c in result['challenges'] if c['type'] == "http-01"][0]
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
    return token, challenge


def challenge_verification_handler(result):
    return json.loads(result.decode('utf8'))


def new_certificate_handler(response):
    result, info = response
    status = info['status']
    if status != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(status, result))

    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64))
    )


def generate_header(account_key):
    pub_hex, pub_exp = crypto.get_rsa_key_public_info(account_key)
    header = {
        "alg": "RS256",
        "jwk": {
            "e": crypto.nopad_b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": crypto.nopad_b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = crypto.nopad_b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
    return header, thumbprint


class ACMEClient(object):

    def __init__(self, ca_directory, account_key, header):
        self.ca_directory = ca_directory
        self.account_key = account_key
        self.header = header

    def get_nonce(self):
        return urlopen(self.ca_directory + "/directory").headers['Replay-Nonce']

    def send_signed_request(self, url, payload, binary=False):
        data = json.dumps(
            self.signed_json_payload(payload, self.get_nonce())
        )
        try:
            resp = urlopen(url, data.encode('utf8'))
            info = dict(status=resp.code)
            info.update(to_lower_case_keys(resp.info()))
            if binary:
                return resp.read(), info
            else:
                return json.loads(resp.read().decode('utf8')), info
        except IOError as e:
            info = dict(status=getattr(e, "code", None))
            if hasattr(e, "info"):
                info.update(to_lower_case_keys(e.info()))
            return getattr(e, "read", e.__str__)().decode('utf8'), info

    def signed_json_payload(self, payload, nonce):
        payload64 = crypto.nopad_b64(json.dumps(payload))
        protected = copy.deepcopy(self.header)
        protected["nonce"] = nonce
        protected64 = crypto.nopad_b64(json.dumps(protected))
        signature = crypto.digest_sign(self.account_key, "{0}.{1}".format(protected64, payload64))
        return {
            "header": self.header, "protected": protected64,
            "payload": payload64, "signature": signature,
        }


def to_lower_case_keys(mapping):
    lcase = {}
    for key, value in mapping.items():
        if hasattr(key, 'lower'):
            key = key.lower()
        lcase[key] = value
    return lcase
