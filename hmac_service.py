"""
hmac_service.py - a real-world style HMAC request-authentication service.

Models how APIs and webhooks (Stripe, GitHub, AWS-style signing) authenticate requests:

  * The signature covers method, path, timestamp, nonce and a hash of the body.
  * The server rejects stale timestamps and repeated nonces (replay protection).
  * Keys have IDs so they can be rotated and revoked.
  * Secrets come from a key store (environment variable or random generation),
    never from source code, and are never included in results or logs.

There is no UI code here; app.py only calls these functions.
"""

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

SIGNATURE_VERSION = "v1"
TOLERANCE_SECONDS = 300          # accept timestamps within +/- 5 minutes
REQUIRED_HEADERS = ("x-key-id", "x-timestamp", "x-nonce", "x-signature")


# --------------------------------------------------------------------------- #
# Key store
# --------------------------------------------------------------------------- #
class KeyStore:
    """Holds shared secrets by key ID. Supports rotation and revocation."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}

    @classmethod
    def from_env(cls, var: str = "HMAC_KEYS") -> "KeyStore":
        """Load keys from an environment variable: 'id1:hexsecret,id2:hexsecret'."""
        store = cls()
        for item in os.environ.get(var, "").split(","):
            if ":" in item:
                key_id, hex_secret = item.strip().split(":", 1)
                store._keys[key_id] = bytes.fromhex(hex_secret)
        return store

    def create_key(self, key_id: str) -> bytes:
        """Generate a random 256-bit secret with the OS CSPRNG and register it."""
        if not key_id:
            raise ValueError("Key ID must not be empty.")
        secret = secrets.token_bytes(32)
        self._keys[key_id] = secret
        return secret

    def get(self, key_id: str) -> Optional[bytes]:
        return self._keys.get(key_id)

    def revoke(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    def key_ids(self) -> List[str]:
        return sorted(self._keys)


# --------------------------------------------------------------------------- #
# Signing (client side)
# --------------------------------------------------------------------------- #
def canonical_string(method: str, path: str, timestamp: int, nonce: str, body: bytes) -> str:
    """Build the exact string that is signed.

    Signing the body's hash (not just a label) binds the signature to the content,
    and including method and path stops a signature for one endpoint being reused
    on another.
    """
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, str(timestamp), nonce, body_hash])


def compute_signature(secret: bytes, canonical: str) -> str:
    """HMAC-SHA256 over the canonical string, as lowercase hex."""
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_request(
    key_id: str,
    secret: bytes,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Return the authentication headers a client attaches to a request."""
    if not key_id or not secret:
        raise ValueError("Key ID and secret are required.")
    if not method or not path:
        raise ValueError("Method and path are required.")
    ts = int(time.time()) if timestamp is None else int(timestamp)
    nonce = nonce or secrets.token_hex(16)
    sig = compute_signature(secret, canonical_string(method, path, ts, nonce, body))
    return {
        "x-key-id": key_id,
        "x-timestamp": str(ts),
        "x-nonce": nonce,
        "x-signature": f"{SIGNATURE_VERSION}={sig}",
    }


# --------------------------------------------------------------------------- #
# Verification (server side)
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    ok: bool
    code: str                                  # OK, MISSING_HEADER, UNKNOWN_KEY, ...
    message: str
    checks: List[Tuple[str, str]] = field(default_factory=list)  # (label, pass|fail|skipped)


CHECK_LABELS = [
    "Required headers present",
    "Key ID known and active",
    "Timestamp within allowed window",
    "Signature format valid",
    "Signature matches (compare_digest)",
    "Nonce not seen before",
]


class Verifier:
    """Server-side verifier with timestamp window and nonce (replay) cache."""

    def __init__(
        self,
        keystore: KeyStore,
        tolerance: int = TOLERANCE_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.keystore = keystore
        self.tolerance = tolerance
        self.clock = clock
        self._seen: Dict[Tuple[str, str], float] = {}   # (key_id, nonce) -> expiry time

    def _purge(self, now: float) -> None:
        self._seen = {k: exp for k, exp in self._seen.items() if exp > now}

    def verify(self, method: str, path: str, headers: Dict[str, str], body: bytes) -> Result:
        checks: List[Tuple[str, str]] = []

        def fail(index: int, code: str, message: str) -> Result:
            done = [(CHECK_LABELS[i], "pass") for i in range(index)]
            rest = [(CHECK_LABELS[i], "skipped") for i in range(index + 1, len(CHECK_LABELS))]
            return Result(False, code, message, done + [(CHECK_LABELS[index], "fail")] + rest)

        h = {k.lower(): (v or "").strip() for k, v in (headers or {}).items()}
        now = self.clock()
        self._purge(now)

        # 1. Required headers
        missing = [name for name in REQUIRED_HEADERS if not h.get(name)]
        if missing or not method or not path:
            return fail(0, "MISSING_HEADER", "A required header, the method or the path is missing.")

        # 2. Key lookup
        key_id = h["x-key-id"]
        secret = self.keystore.get(key_id)
        if secret is None:
            return fail(1, "UNKNOWN_KEY", "Key ID is unknown or has been revoked.")

        # 3. Timestamp window (cheap check first, limits replay window)
        try:
            ts = int(h["x-timestamp"])
        except ValueError:
            return fail(2, "EXPIRED", "Timestamp is not a valid integer.")
        if abs(now - ts) > self.tolerance:
            return fail(2, "EXPIRED", f"Timestamp is outside the allowed window of {self.tolerance} seconds.")

        # 4. Signature format
        version, _, hex_sig = h["x-signature"].partition("=")
        try:
            received = bytes.fromhex(hex_sig)
            if version != SIGNATURE_VERSION or len(received) != 32:
                raise ValueError
        except ValueError:
            return fail(3, "BAD_SIGNATURE", "Signature is not in the form v1=<64 hex characters>.")

        # 5. Recompute and compare in constant time
        expected = compute_signature(secret, canonical_string(method, path, ts, h["x-nonce"], body))
        if not hmac.compare_digest(bytes.fromhex(expected), received):
            return fail(4, "BAD_SIGNATURE", "Signature does not match. The request or the key was altered.")

        # 6. Replay protection. The nonce is stored only AFTER the signature is valid,
        #    so unauthenticated requests cannot fill the cache.
        nonce_key = (key_id, h["x-nonce"])
        if nonce_key in self._seen:
            return fail(5, "REPLAY", "This nonce was already used. The request is a replay.")
        self._seen[nonce_key] = ts + self.tolerance

        return Result(True, "OK", "Request authenticated.", [(c, "pass") for c in CHECK_LABELS])


# --------------------------------------------------------------------------- #
# Attack scenarios (used by the UI and tests)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ScenarioResult:
    name: str
    description: str
    expected: str
    actual: str

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


def run_scenarios() -> List[ScenarioResult]:
    """Run nine scenarios on a fresh key store and verifier with random keys."""
    store = KeyStore()
    secret = store.create_key("key-1")
    verifier = Verifier(store)
    method, path = "POST", "/v1/payments"
    body = b'{"to":"alice","amount":500}'

    def signed(**kw):
        return sign_request("key-1", secret, method, path, body, **kw)

    def run(m=method, p=path, headers=None, b=body, v=None):
        return (v or verifier).verify(m, p, headers, b).code

    out: List[ScenarioResult] = []

    def add(name, desc, expected, actual):
        out.append(ScenarioResult(name, desc, expected, actual))

    h = signed()
    add("Valid request", "Correct key, fresh timestamp, new nonce.", "OK", run(headers=h))
    add("Replayed request", "The exact same request is sent again.", "REPLAY", run(headers=h))
    add("Tampered body", "Amount changed from 500 to 9000.", "BAD_SIGNATURE",
        run(headers=signed(), b=b'{"to":"alice","amount":9000}'))
    add("Tampered path", "Signature reused on a different endpoint.", "BAD_SIGNATURE",
        run(p="/v1/refunds", headers=signed()))
    add("Tampered method", "Signature reused with a different HTTP method.", "BAD_SIGNATURE",
        run(m="DELETE", headers=signed()))
    attacker_secret = secrets.token_bytes(32)
    add("Wrong secret key", "Attacker signs with a guessed key.", "BAD_SIGNATURE",
        run(headers=sign_request("key-1", attacker_secret, method, path, body)))
    forged = signed()
    forged["x-signature"] = forged["x-signature"][:-1] + ("0" if forged["x-signature"][-1] != "0" else "1")
    add("Modified signature", "One character of the signature changed.", "BAD_SIGNATURE", run(headers=forged))
    add("Expired timestamp", "Request signed 10 minutes ago.", "EXPIRED",
        run(headers=signed(timestamp=int(time.time()) - 600)))
    store2 = KeyStore(); old = store2.create_key("old-key"); store2.create_key("new-key")
    v2 = Verifier(store2); store2.revoke("old-key")
    add("Revoked key", "Key was rotated out; old key is used.", "UNKNOWN_KEY",
        run(headers=sign_request("old-key", old, method, path, body), v=v2))
    return out
