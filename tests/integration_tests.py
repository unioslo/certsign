import unittest, socket, tempfile

from certsign import client, crypto

from .settings import *

STAGING_CA_DIRECTORY = "https://acme-staging.api.letsencrypt.org"


class ClientIntegrationTest(unittest.TestCase):

    def test_sign_host_csr(self):
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
        self.assertEqual(cert_domains, {hostname})
        self.assertEqual(valid_days, 89)

test_suite = unittest.TestSuite([
    unittest.defaultTestLoader.loadTestsFromTestCase(ClientIntegrationTest),
])

