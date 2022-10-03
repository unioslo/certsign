import unittest, tempfile

from certsign import crypto
from .settings import *


class CryptoTest(unittest.TestCase):

    def test_get_rsa_public_info(self):
        pub_hex, pub_exp = crypto.get_rsa_key_public_info(ACCOUNT_KEY)
        self.assertEqual(pub_exp, ACCOUNT_KEY_EXP)
        self.assertEqual(pub_hex, ACCOUNT_KEY_HEX)

    def test_digest_sign(self):
        expected_signature = \
            "BElwZ5PqGwdknAJjrI08A3foLGll5wol4kvk0g_GG6fe77kHP1sYYscz5Ay6BxHdsFF0jsFUFfpV-pXJll" \
            "NebOR5bLodrVXHitSZwwKDmYrN_bCwwk0WJKn4Cic39SAjJe5GZ9hVCrkoz7Y9n0vnbJa8lLosexUXZgrH" \
            "1TRSJXdEGBBOcRvuMBllVbDco8aZ8AeqcZsFwBk9qDoSDgcMzNThhfl5Mqi5TzDjGIUeCiMrSVsi9I50zX" \
            "dmg910oZQWYfB3Sr9pX-PVRQrhgXUF39TPitlQkfAhpsTJWgVS6fOt11jCdiSR2CvJyYvytv7bc5yHYiOV" \
            "RlOMiCoOdQUnttblMckB4c0RK48SlmoYhb2nJRjSwvtACr0SJl3gPf0yyrwfynp4oPwoVNuWsPrfYfxKCz" \
            "uYMWJoWEliVROGzp1sGmOXDTbbN-gzmoN1i4Dfg8JNvDg8gt9ouQm1WTYHcqLCV0kg94kPq7lyCFb3vpAC" \
            "mF7fXihVpE_Z4u2DmIvbgVX0M1V1nUDb6I-52eqB2DePfYM6yLU1hezMZG50Zgl_1eGmqT1iyhhfsD5ksV" \
            "fODHs47bj9Qdy5ZAPEU6j_WbZ1rvtri73EYkAjp0F28IgDJidsl4SwlBKYavIWQBNXA7JzwPeIgVfQyVj2" \
            "1HrYB5-Oy1G0PILMRI6seXr8oRI"
        signature = crypto.digest_sign(ACCOUNT_KEY, "test")
        self.assertEqual(signature, expected_signature)

    def test_get_csr_domains(self):
        domains = crypto.get_csr_domains(CSR_FILE)
        self.assertSequenceEqual(domains, {'test.domain', 'www.test.domain'})

    def test_csr_to_der_fomat(self):
        csr_der = crypto.csr_to_der_format(CSR_FILE)
        self.assertTrue(len(csr_der) > 0)

    def test_self_signed_single_domain_cert(self):
        csr = crypto.create_csr(
            PRIVKEY,
            ["domain1.example"],
            openssl_conf=OPENSSL_CONF,
        )
        with tempfile.NamedTemporaryFile() as csr_file:
            csr_file.write(csr)
            csr_file.flush()
            cert = crypto.self_sign_csr(csr_file.name, PRIVKEY, valid_days=90)

        with tempfile.NamedTemporaryFile() as cert_file:
            cert_file.write(cert)
            cert_file.flush()
            cert_domains = crypto.get_cert_domains(cert_file.name)
            valid_days = crypto.get_cert_days(cert_file.name)
        self.assertIn(valid_days, (89, 90))
        self.assertSequenceEqual(cert_domains, {"domain1.example"})

    def test_self_signed_muliple_domain_cert(self):
        cert = crypto.self_sign_csr(CSR_FILE, PRIVKEY, valid_days=90)
        csr_domains = crypto.get_csr_domains(CSR_FILE)

        with tempfile.NamedTemporaryFile() as cert_file:
            cert_file.write(cert)
            cert_file.flush()
            cert_domains = crypto.get_cert_domains(cert_file.name)
            valid_days = crypto.get_cert_days(cert_file.name)
        self.assertIn(valid_days, (89, 90))
        self.assertSequenceEqual(cert_domains, csr_domains)

    def test_create_single_domain_csr(self):
        csr = crypto.create_csr(
            PRIVKEY,
            ["domain1.example"],
            DNAME,
            OPENSSL_CONF,
        )
        with tempfile.NamedTemporaryFile() as csr_file:
            csr_file.write(csr)
            csr_file.flush()
            csr_domains = crypto.get_csr_domains(csr_file.name)
        self.assertEqual(csr_domains, {"domain1.example"})

    def test_create_multiple_domain_csr(self):
        csr = crypto.create_csr(
            PRIVKEY,
            ["domain1.example", "www.domain1.example"],
            DNAME,
            OPENSSL_CONF
        )
        with tempfile.NamedTemporaryFile() as csr_file:
            csr_file.write(csr)
            csr_file.flush()
            csr_domains = crypto.get_csr_domains(csr_file.name)
        self.assertEqual(csr_domains, {"domain1.example", "www.domain1.example"})

    def test_create_private_key(self):
        privkey = crypto.create_private_key(1024).decode('utf8')
        self.assertTrue("-----BEGIN PRIVATE KEY-----" in privkey)
        self.assertTrue("-----END PRIVATE KEY-----" in privkey)
