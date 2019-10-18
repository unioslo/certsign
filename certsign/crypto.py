import os, subprocess, base64, re, time, tempfile
from datetime import datetime

OPENSSL_BIN = "openssl"
PEM_TYPE_MAP = {
    "-----BEGIN CERTIFICATE REQUEST-----": "CSR",
    "-----BEGIN CERTIFICATE-----": "CERT"
}


def get_rsa_key_public_info(key):
    """
    Parses an RSA key file in PEM format and returns the modulus
    and public exponent of the key
    """
    proc = subprocess.Popen(
        [OPENSSL_BIN, "rsa", "-in", key, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp

    return pub_hex, pub_exp


def digest_sign(key, message):
    proc = subprocess.Popen(
        [OPENSSL_BIN, "dgst", "-sha256", "-sign", key],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate(message.encode('utf8'))
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    return nopad_b64(out)


def pem_file_info(pem_file):
    pem_type = detect_pem_type(pem_file)
    if pem_type == "CSR":
        return csr_info(pem_file)
    elif pem_type == "CERT":
        return cert_info(pem_file)
    else:
        raise TypeError("Not a known PEM file type")


def detect_pem_type(a_file):
    pem_type = None
    with open(a_file, 'r') as f:
        for line in f:
            marker = line.strip()
            if marker in PEM_TYPE_MAP:
                pem_type = PEM_TYPE_MAP[marker]
                break
    return pem_type


def csr_info(csr_file):
    proc = subprocess.Popen(
        [OPENSSL_BIN, "req", "-in", csr_file, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr_file, err))

    return out.decode('utf8')


def cert_info(cert_file):
    proc = subprocess.Popen(
        [OPENSSL_BIN, "x509", "-in", cert_file, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(cert_file, err))

    return out.decode('utf8')


def get_csr_domains(csr_file):
    return retrieve_domains(csr_info(csr_file))


def get_cert_domains(cert_file):
    return retrieve_domains(cert_info(cert_file))


def retrieve_domains(buffer):
    domains = set()
    common_name = re.search(r"Subject:.*? CN\s*=\s*([^\s,;/]+)", buffer)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
        buffer,
        re.MULTILINE|re.DOTALL
    )
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    return domains


def csr_to_der_format(csr_file):
    proc = subprocess.Popen(
        [OPENSSL_BIN, "req", "-in", csr_file, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    csr_der, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    return nopad_b64(csr_der)


def get_cert_days(cert_file):
    """
    Return the days the certificate in cert_file remains valid and -1
    if the file was not found.

    :param unicode cert_file:
    :return unicode:
    """
    _cert_file = os.path.expanduser(cert_file)
    if not os.path.exists(_cert_file):
        return -1

    proc = subprocess.Popen(
        [OPENSSL_BIN, "x509", "-in", _cert_file, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    not_after_str = re.search(r"\s+Not After\s*:\s+(.*)", out.decode('utf8')).group(1)
    not_after = datetime.fromtimestamp(
        time.mktime(time.strptime(not_after_str,'%b %d %H:%M:%S %Y %Z'))
    )

    now = datetime.utcnow()
    return (not_after - now).days


def self_sign_csr(csr_file, privkey, valid_days):
    """
    Returns a self signed certificate in the PEM format.

    :param unicode csr_file:
    :param unicode privkey:
    :return unicode:
    """
    domains = get_csr_domains(csr_file)

    openssl_cert_cmd = [
        OPENSSL_BIN, "x509", "-req", "-sha256",
        "-days", str(valid_days),
        "-in", csr_file,
        "-signkey", privkey,
    ]
    if len(domains) > 1:
        with tempfile.NamedTemporaryFile() as extfile:
            san_extension = "subjectAltName="
            for domain in domains:
                san_extension += "DNS:{},".format(domain)
            san_extension = san_extension.rstrip(',')
            extfile.write(san_extension.encode('utf8'))
            extfile.flush()
            openssl_cert_cmd.extend(["-extfile", extfile.name])
            proc = subprocess.Popen(
                openssl_cert_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = proc.communicate()
    else:
        proc = subprocess.Popen(
            openssl_cert_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate()

    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    self_signed_cert = out.decode('utf8')
    return self_signed_cert


def create_csr(privkey, domains, dname=None, openssl_conf='/etc/ssl/openssl.cnf'):
    cn = domains[0]
    subject = "/CN={}/{}".format(cn, dname or '')
    openssl_req_command = [
        OPENSSL_BIN, "req", "-new", "-sha256",
        "-subj", subject,
        "-key", privkey
    ]
    if len(domains) > 1:
        with tempfile.NamedTemporaryFile() as tmp_conf, open(openssl_conf) as conf:
            tmp_conf.write(conf.read().encode('utf8'))
            san_extension = "\n[SAN]\nsubjectAltName="
            for domain in domains:
                san_extension += "DNS:{},".format(domain)
            san_extension = san_extension.rstrip(',')
            tmp_conf.write(san_extension.encode('utf8'))
            tmp_conf.flush()
            openssl_req_command.extend([
                "-reqexts", "SAN",
                "-config", tmp_conf.name
            ])
            proc = subprocess.Popen(
                openssl_req_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = proc.communicate()
    else:
        proc = subprocess.Popen(
            openssl_req_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate()

    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    csr = out.decode('utf8')
    return csr


def create_private_key(bits):
    proc = subprocess.Popen(
        [OPENSSL_BIN, "genrsa", str(bits)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    key = out.decode('utf8')
    return key


def nopad_b64(b):
    """helper function base64 encode for jose spec"""
    if not isinstance(b, bytes):
        b = b.encode('utf8')
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")
