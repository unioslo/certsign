import socket, tempfile
import pytest

from certsign import client, crypto
from .settings import *

STAGING_CA_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


@pytest.mark.integration
def sign_host_csr_test():
    hostname = socket.getfqdn()
    csr = crypto.create_csr(PRIVKEY, [hostname], DNAME, OPENSSL_CONF)
    with tempfile.NamedTemporaryFile() as csr_file:
        csr_file.write(csr.encode('utf8'))
        csr_file.flush()
        signed_cert = client.sign_csr(
            ACCOUNT_KEY,
            csr_file.name,
            CHALLENGE_DIR,
            account_email='test@example.com',
            ca_directory=STAGING_CA_DIRECTORY,
        )
    with tempfile.NamedTemporaryFile() as cert_file:
        cert_file.write(signed_cert.encode('utf8'))
        cert_file.flush()
        cert_domains = crypto.get_cert_domains(cert_file.name)
        valid_days = crypto.get_cert_days(cert_file.name)
    assert cert_domains == {hostname}
    assert valid_days in (89, 90)
