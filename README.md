# HMAC Request Authentication: A Real-World Model

A working model of how APIs and webhooks (Stripe, GitHub, AWS-style signing) use HMAC to authenticate requests.

## What is HMAC?

HMAC (Hash-based Message Authentication Code, RFC 2104) uses a shared secret key and a hash function to produce a tag that proves **integrity** (the message was not changed) and **authenticity** (it came from a key holder).

```
HMAC(K, m) = SHA256( (K xor opad) || SHA256( (K xor ipad) || m ) )
```

A plain hash is not enough because anyone can recompute it. HMAC does **not** encrypt the message and does **not** provide non-repudiation (both sides hold the key).

## What makes this "real world"

| Real-life practice | Where it is implemented |
|---|---|
| Sign method, path, timestamp, nonce and body hash, not just the message | `canonical_string()` |
| Send signature in headers (`x-key-id`, `x-timestamp`, `x-nonce`, `x-signature: v1=...`) | `sign_request()` |
| Constant-time comparison | `hmac.compare_digest()` in `Verifier.verify()` |
| Reject stale requests (5-minute window) | timestamp check |
| Reject replays with a nonce cache, stored only after the signature is valid | nonce check |
| Key IDs, rotation, revocation | `KeyStore` |
| Secrets from environment or CSPRNG, never in code or logs | `KeyStore.from_env()`, `create_key()` |

## Files

| File | Purpose |
|---|---|
| `hmac_service.py` | Signing, verification, key store, replay protection, attack scenarios (no UI code) |
| `app.py` | Streamlit demo: Overview, Client, Server, Attack Scenarios |
| `tests.py` | 18 automated tests |
| `requirements.txt` | Dependencies (Streamlit) |
| `.streamlit/config.toml` | Dark theme |

## Install and run

```bash
pip install -r requirements.txt
streamlit run app.py
python -m unittest tests -v
```

## Using the demo

1. **Client:** select **Sign request**, then **Send to Server**.
2. **Server:** select **Verify request** and see the six checks pass.
3. Select **Verify request** again to see the replay rejected.
4. Edit the body, path, timestamp or signature, or move the time slider past 300 seconds, and verify again.
5. Use **Key management** to create or revoke keys.
6. **Attack Scenarios:** run all nine automatically.

## Expected results

| Scenario | Result |
|---|---|
| Valid request | `OK` |
| Replayed request | `REPLAY` |
| Tampered body, path or method | `BAD_SIGNATURE` |
| Wrong secret key | `BAD_SIGNATURE` |
| Modified signature | `BAD_SIGNATURE` |
| Timestamp older than 5 minutes | `EXPIRED` |
| Revoked key | `UNKNOWN_KEY` |

## Limitations

- The nonce cache is in memory. A production system with several servers needs a shared store such as Redis.
- Both parties hold the same key, so HMAC cannot prove which of them created a message. Digital signatures can.
- The body is not encrypted. Use TLS.
- Key distribution is assumed to happen securely outside this app. Keys are random per session here, so the client and server run in one process.
- Real servers return a generic 401 to clients; this demo shows specific reasons for teaching.
