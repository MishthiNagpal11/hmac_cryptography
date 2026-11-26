"""Tests for the four required verification scenarios. Run: python -m unittest tests -v"""

import unittest

import crypto_utils as cu

MESSAGE = "Transfer 500 to account 1234"
KEY = "shared-secret-for-testing"


class TestVerificationScenarios(unittest.TestCase):
    def setUp(self):
        self.tag = cu.generate_hmac(MESSAGE, KEY)

    def test_1_original_message_correct_key_succeeds(self):
        self.assertTrue(cu.verify_hmac(MESSAGE, KEY, self.tag)[0])

    def test_2_modified_message_fails(self):
        self.assertFalse(cu.verify_hmac("Transfer 900 to account 1234", KEY, self.tag)[0])

    def test_3_incorrect_key_fails(self):
        self.assertFalse(cu.verify_hmac(MESSAGE, "a-different-key", self.tag)[0])

    def test_4_modified_tag_fails(self):
        modified = ("0" if self.tag[0] != "0" else "1") + self.tag[1:]
        self.assertFalse(cu.verify_hmac(MESSAGE, KEY, modified)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
