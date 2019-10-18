import unittest, json, binascii, re

from certsign import client, crypto
from .settings import *

TEST_CA_DIRECTORY = {
    "newNonce": "https://example.com/acme/new-nonce",
    "newAccount": "https://example.com/acme/new-account",
    "newOrder": "https://example.com/acme/new-order",
    "newAuthz": "https://example.com/acme/new-authz",
    "revokeCert": "https://example.com/acme/revoke-cert",
    "keyChange": "https://example.com/acme/key-change",
    "meta": {
        "termsOfService": "https://example.com/acme/terms/2017-5-30",
        "website": "https://www.example.com/",
        "caaIdentities": ["example.com"],
        "externalAccountRequired": False
    }
}


class ClientTest(unittest.TestCase):

    def test_signed_json_payload(self):
        jwk = {
            "e": "tullball",
            "kty": "RSA",
            "n": "tullball",
        }
        acme_client = client.ACMEClient(TEST_CA_DIRECTORY, ACCOUNT_KEY, jwk)
        payload = {'resource':'reg'}
        signed_payload = acme_client.signed_json_payload(
            url=TEST_CA_DIRECTORY["newAccount"],
            payload=payload,
            nonce="tullball"
        )
        self.assertEqual(
            signed_payload['payload'],
            crypto.nopad_b64(json.dumps(payload))
        )
        self.assertTrue(len(signed_payload['protected']) > 0)
        self.assertTrue(len(signed_payload['signature']) > 0)

    def test_generate_jwk(self):
        expected_thumbprint = "ldZUDGK6ZLu07lWKqj4ROiQ5Wpl9HUesRgyTom79JUA"
        jwk, thumbprint = client.generate_jwk(ACCOUNT_KEY)
        self.assertEqual(thumbprint, expected_thumbprint)
        self.assertEqual(
            jwk['e'],
            crypto.nopad_b64(binascii.unhexlify(ACCOUNT_KEY_EXP.encode("utf-8")))
        )
        self.assertEqual(
            jwk['n'],
            crypto.nopad_b64(binascii.unhexlify(
                re.sub(r"(\s|:)", "", ACCOUNT_KEY_HEX).encode("utf-8")
            ))
        )
