"""Tests for hmac_service.py. Run: python -m unittest tests -v"""

import time
import unittest

import hmac_service as hs

METHOD, PATH, BODY = "POST", "/v1/payments", b'{"to":"alice","amount":500}'


class TestService(unittest.TestCase):
    def setUp(self):
        self.store = hs.KeyStore()
        self.secret = self.store.create_key("key-1")
        self.now = 1_700_000_000.0
        self.verifier = hs.Verifier(self.store, clock=lambda: self.now)

    def sign(self, **kw):
        kw.setdefault("timestamp", int(self.now))
        return hs.sign_request("key-1", self.secret, METHOD, PATH, BODY, **kw)

    def check(self, headers, method=METHOD, path=PATH, body=BODY):
        return self.verifier.verify(method, path, headers, body)

    def test_valid_request(self):
        r = self.check(self.sign())
        self.assertTrue(r.ok)
        self.assertEqual(r.code, "OK")

    def test_tampered_body(self):
        self.assertEqual(self.check(self.sign(), body=b'{"amount":9000}').code, "BAD_SIGNATURE")

    def test_tampered_path_and_method(self):
        self.assertEqual(self.check(self.sign(), path="/v1/refunds").code, "BAD_SIGNATURE")
        self.assertEqual(self.check(self.sign(), method="DELETE").code, "BAD_SIGNATURE")

    def test_wrong_secret(self):
        h = hs.sign_request("key-1", b"x" * 32, METHOD, PATH, BODY, timestamp=int(self.now))
        self.assertEqual(self.check(h).code, "BAD_SIGNATURE")

    def test_modified_signature(self):
        h = self.sign()
        h["x-signature"] = h["x-signature"][:-1] + ("0" if h["x-signature"][-1] != "0" else "1")
        self.assertEqual(self.check(h).code, "BAD_SIGNATURE")

    def test_malformed_signature(self):
        h = self.sign(); h["x-signature"] = "v1=zzzz"
        self.assertEqual(self.check(h).code, "BAD_SIGNATURE")

    def test_expired_and_future_timestamp(self):
        self.assertEqual(self.check(self.sign(timestamp=int(self.now) - 600)).code, "EXPIRED")
        self.assertEqual(self.check(self.sign(timestamp=int(self.now) + 600)).code, "EXPIRED")

    def test_replay_rejected(self):
        h = self.sign()
        self.assertTrue(self.check(h).ok)
        self.assertEqual(self.check(h).code, "REPLAY")

    def test_failed_request_does_not_burn_nonce(self):
        h = self.sign(nonce="n1")
        bad = dict(h); bad["x-signature"] = "v1=" + "0" * 64
        self.assertEqual(self.check(bad).code, "BAD_SIGNATURE")
        self.assertTrue(self.check(h).ok)

    def test_nonce_cache_expires(self):
        h = self.sign()
        self.assertTrue(self.check(h).ok)
        self.now += 301     # past the window, entry is purged; timestamp is now stale anyway
        self.assertEqual(self.check(h).code, "EXPIRED")

    def test_unknown_key_and_missing_header(self):
        h = self.sign(); h["x-key-id"] = "nope"
        self.assertEqual(self.check(h).code, "UNKNOWN_KEY")
        h = self.sign(); del h["x-nonce"]
        self.assertEqual(self.check(h).code, "MISSING_HEADER")

    def test_key_rotation_and_revocation(self):
        new_secret = self.store.create_key("key-2")
        h2 = hs.sign_request("key-2", new_secret, METHOD, PATH, BODY, timestamp=int(self.now))
        self.assertTrue(self.check(h2).ok)
        old = self.sign(); self.store.revoke("key-1")
        self.assertEqual(self.check(old).code, "UNKNOWN_KEY")

    def test_empty_body_allowed_for_get(self):
        h = hs.sign_request("key-1", self.secret, "GET", "/v1/me", b"", timestamp=int(self.now))
        self.assertTrue(self.check(h, "GET", "/v1/me", b"").ok)

    def test_header_names_case_insensitive(self):
        h = {k.upper(): v for k, v in self.sign().items()}
        self.assertTrue(self.check(h).ok)

    def test_results_do_not_contain_secret(self):
        r = self.check(self.sign(timestamp=1))
        self.assertNotIn(self.secret.hex(), repr(r))

    def test_keystore_from_env(self):
        import os
        os.environ["HMAC_KEYS_TEST"] = "a:" + "11" * 32
        self.assertEqual(hs.KeyStore.from_env("HMAC_KEYS_TEST").get("a"), bytes.fromhex("11" * 32))

    def test_known_hmac_vector(self):  # RFC 4231 test case 2
        self.assertEqual(
            hs.compute_signature(b"Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_all_scenarios_behave_as_expected(self):
        results = hs.run_scenarios()
        self.assertEqual(len(results), 9)
        for r in results:
            self.assertTrue(r.passed, r.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
