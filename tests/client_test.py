import unittest, json, binascii, re

from certsign import client, crypto
from .settings import *

TEST_CA_DIRECTORY = "https://acme.example.com"


class ClientTest(unittest.TestCase):

    def test_signed_json_payload(self):
        header = {
            "alg": "RS256",
            "jwk": {
                "e": "tullball",
                "kty": "RSA",
                "n": "tullball",
            },
        }
        acme_client = client.ACMEClient(TEST_CA_DIRECTORY, ACCOUNT_KEY, header)
        payload = {'resource':'reg'}
        signed_payload = acme_client.signed_json_payload(
            payload=payload,
            nonce="tullball"
        )
        self.assertEqual(signed_payload['payload'], crypto.nopad_b64(json.dumps(payload)))
        self.assertTrue(len(signed_payload['protected']) > 0)
        self.assertTrue(len(signed_payload['signature']) > 0)

    def test_generate_headers(self):
        expected_thumbprint = "ldZUDGK6ZLu07lWKqj4ROiQ5Wpl9HUesRgyTom79JUA"
        header, thumbprint = client.generate_header(ACCOUNT_KEY)
        self.assertEqual(thumbprint, expected_thumbprint)
        self.assertEqual(
            header['jwk']['e'],
            crypto.nopad_b64(binascii.unhexlify(ACCOUNT_KEY_EXP.encode("utf-8")))
        )
        self.assertEqual(
            header['jwk']['n'],
            crypto.nopad_b64(
                binascii.unhexlify(re.sub(r"(\s|:)", "", ACCOUNT_KEY_HEX).encode("utf-8")))
        )


