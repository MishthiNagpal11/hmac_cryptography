"""Cryptographic functions for the HMAC-Based Message Authentication System."""

import hashlib
import hmac

TAG_HEX_LENGTH = 64  # HMAC-SHA256 output: 32 bytes = 64 hex characters


def generate_hmac(message: str, key: str) -> str:
    """Return the HMAC-SHA256 tag of `message` under the shared secret `key` (hex)."""
    if not message:
        raise ValueError("Message must not be empty.")
    if not key:
        raise ValueError("Secret key must not be empty.")
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def plain_sha256(message: str) -> str:
    """Return the plain SHA-256 hash of `message` (no key, so no authentication)."""
    if not message:
        raise ValueError("Message must not be empty.")
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def verify_hmac(message: str, key: str, received_tag: str):
    """Recompute the HMAC and compare it with the received tag.

    Returns (success, explanation). The key is never included in the output.
    """
    tag = (received_tag or "").strip()
    if len(tag) != TAG_HEX_LENGTH:
        return False, f"Invalid tag: it must be {TAG_HEX_LENGTH} hexadecimal characters."
    try:
        received = bytes.fromhex(tag)
    except ValueError:
        return False, "Invalid tag: it contains non-hexadecimal characters."
    try:
        calculated = generate_hmac(message, key)
    except ValueError as exc:
        return False, str(exc)

    # compare_digest compares in constant time.
    if hmac.compare_digest(bytes.fromhex(calculated), received):
        return True, "Verification successful: the calculated HMAC matches the received tag."
    return False, "Verification unsuccessful: the calculated HMAC does not match the received tag."


def run_four_scenarios(message: str, key: str):
    """Run the four required verification scenarios.

    Returns a list of (name, expected_success, actual_success).
    """
    tag = generate_hmac(message, key)
    modified_message = message[:-1] + ("!" if message[-1] != "!" else "?")
    wrong_key = key + "x"
    modified_tag = ("0" if tag[0] != "0" else "1") + tag[1:]

    return [
        ("1. Original message, correct key", True, verify_hmac(message, key, tag)[0]),
        ("2. Modified message, original tag", False, verify_hmac(modified_message, key, tag)[0]),
        ("3. Original message, incorrect key", False, verify_hmac(message, wrong_key, tag)[0]),
        ("4. Original message, modified tag", False, verify_hmac(message, key, modified_tag)[0]),
    ]
