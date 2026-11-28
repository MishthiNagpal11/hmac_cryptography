"""
app.py - Streamlit demo of a real-world HMAC request-authentication model.

Tabs: Overview, Client (signs), Server (verifies), Attack Scenarios.
All cryptography lives in hmac_service.py. Secrets are generated randomly per
session, never shown, never logged, and never hardcoded.

Run: streamlit run app.py
"""

import time
from html import escape

import streamlit as st

import hmac_service as hs

st.set_page_config(page_title="HMAC Request Authentication", page_icon="🛡️", layout="centered")

st.markdown(
    """
    <style>
    .block-container { padding-top: 4rem; max-width: 880px; }
    .app-header { border: 1px solid #1f3558; border-left: 4px solid #22d3ee; border-radius: 10px;
                  background: linear-gradient(135deg, #10203d 0%, #0b1426 80%);
                  padding: 1.1rem 1.4rem; margin-bottom: 1.2rem; }
    .app-header h1 { font-size: 1.6rem; margin: 0; padding: 0; color: #e6edf7; }
    .app-header p { margin: .3rem 0 0 0; color: #8da2c0; font-size: .95rem; }
    h3 { color: #22d3ee; }
    .stTabs [data-baseweb="tab-list"] { gap: 6px; border-bottom: 1px solid #1f3558; }
    .stTabs [data-baseweb="tab"] { background: #101c33; border-radius: 8px 8px 0 0;
                                   padding: .5rem 1rem; color: #8da2c0; }
    .stTabs [aria-selected="true"] { background: #13213b; color: #22d3ee; }
    div[data-testid="stCode"] pre { border: 1px solid #1f3558; border-radius: 8px;
                                    background: #0a1120 !important; }
    div[data-testid="stCode"] code { color: #22d3ee !important; white-space: pre-wrap !important;
                                     word-break: break-all; }
    .stTextArea textarea, .stTextInput input { background: #0a1120; border: 1px solid #1f3558; }
    .stButton > button { border-radius: 8px; border: 1px solid #1f3558; }
    .stButton > button[kind="primary"] { background: #22d3ee; border-color: #22d3ee;
                                         color: #0b1426; font-weight: 600; }
    .stButton > button[kind="primary"]:hover { background: #34d399; border-color: #34d399; }
    .check { padding: .35rem .8rem; border: 1px solid #1f3558; border-radius: 8px;
             margin-bottom: .35rem; background: #101c33; }
    .check.pass { border-left: 4px solid #34d399; } .check.fail { border-left: 4px solid #f87171; }
    .check.skipped { border-left: 4px solid #3b4a63; color: #6c7f9e; }
    </style>
    <div class="app-header">
      <h1>🛡️ HMAC Request Authentication</h1>
      <p>Signed requests with timestamp, nonce, replay protection and key rotation</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------- state
if "store" not in st.session_state:
    store = hs.KeyStore()
    store.create_key("key-1")                      # random 256-bit secret, never displayed
    st.session_state["store"] = store
    st.session_state["verifier"] = hs.Verifier(store)
store: hs.KeyStore = st.session_state["store"]
verifier: hs.Verifier = st.session_state["verifier"]


def send_to_server() -> None:
    """Callback: put the signed request 'on the wire' (the Server tab fields)."""
    req = st.session_state.get("signed")
    if req:
        h = req["headers"]
        st.session_state.update(
            srv_method=req["method"], srv_path=req["path"], srv_key_id=h["x-key-id"],
            srv_ts=h["x-timestamp"], srv_nonce=h["x-nonce"], srv_sig=h["x-signature"],
            srv_body=req["body"],
        )
        st.session_state["sent"] = True


tab_over, tab_client, tab_server, tab_attack = st.tabs(
    ["Overview", "Client", "Server", "Attack Scenarios"]
)

# --------------------------------------------------------------------------- overview
with tab_over:
    st.subheader("How it works")
    st.markdown(
        """
**HMAC** proves a message was not changed and came from a holder of a shared secret key:
`HMAC(K, m) = SHA256((K ⊕ opad) ‖ SHA256((K ⊕ ipad) ‖ m))`.

Real systems sign more than the message. The **client** signs this canonical string:

```
METHOD \\n PATH \\n TIMESTAMP \\n NONCE \\n SHA256(BODY)
```

and sends four headers: `x-key-id`, `x-timestamp`, `x-nonce`, `x-signature: v1=<hex>`.

The **server** then checks, in order:
1. all headers are present
2. the key ID exists and is not revoked
3. the timestamp is within ±5 minutes
4. the signature format is valid
5. the recomputed HMAC matches, using `hmac.compare_digest()`
6. the nonce has not been used before (replay protection)

HMAC gives integrity and shared-key authentication. It does **not** encrypt the body
(use TLS) and does **not** give non-repudiation (both sides hold the key).
        """
    )

# --------------------------------------------------------------------------- client
with tab_client:
    st.subheader("Client: sign a request")
    c1, c2 = st.columns(2)
    key_id = c1.selectbox("Key ID", store.key_ids() or ["(none)"], key="cl_key")
    method = c2.selectbox("Method", ["POST", "GET", "PUT", "DELETE"], key="cl_method")
    path = st.text_input("Path", value="/v1/payments", key="cl_path")
    body = st.text_area("Body", value='{"to": "alice", "amount": 500}', key="cl_body", height=100)

    if st.button("Sign request", type="primary"):
        secret = store.get(key_id)
        try:
            headers = hs.sign_request(key_id, secret, method, path, body.encode("utf-8"))
            st.session_state["signed"] = {"method": method, "path": path, "body": body,
                                          "headers": headers}
            st.session_state["sent"] = False
        except ValueError as exc:
            st.session_state.pop("signed", None)
            st.error(str(exc))

    signed = st.session_state.get("signed")
    if signed:
        st.success("Request signed.")
        h = signed["headers"]
        st.write("String that was signed")
        st.code(hs.canonical_string(signed["method"], signed["path"], int(h["x-timestamp"]),
                                    h["x-nonce"], signed["body"].encode("utf-8")), language=None)
        st.write("Headers sent with the request")
        st.code("\n".join(f"{k}: {v}" for k, v in h.items()), language=None)
        st.button("Send to Server", on_click=send_to_server)
        if st.session_state.get("sent"):
            st.info("Sent. Open the Server tab. You can edit any field there to play the attacker.")

# --------------------------------------------------------------------------- server
with tab_server:
    st.subheader("Server: verify a request")
    st.caption("These fields are what arrived over the network. Edit them to simulate an attacker.")
    s1, s2 = st.columns(2)
    s_method = s1.text_input("Method", key="srv_method")
    s_path = s2.text_input("Path", key="srv_path")
    s_body = st.text_area("Body", key="srv_body", height=90)
    s3, s4 = st.columns(2)
    s_key = s3.text_input("x-key-id", key="srv_key_id")
    s_ts = s4.text_input("x-timestamp", key="srv_ts")
    s_nonce = st.text_input("x-nonce", key="srv_nonce")
    s_sig = st.text_input("x-signature", key="srv_sig")

    offset = st.slider("Simulate time passing on the server (seconds)", 0, 900, 0, step=30,
                       help="Above 300 seconds, a normally signed request becomes stale.")
    verifier.clock = lambda: time.time() + offset

    if st.button("Verify request", type="primary"):
        headers = {"x-key-id": s_key, "x-timestamp": s_ts, "x-nonce": s_nonce, "x-signature": s_sig}
        try:
            res = verifier.verify(s_method, s_path, headers, s_body.encode("utf-8"))
        except Exception:
            st.error("Unexpected error while verifying.")
        else:
            (st.success if res.ok else st.error)(f"{res.code}: {res.message}")
            for label, status in res.checks:
                icon = {"pass": "✓", "fail": "✗", "skipped": "–"}[status]
                st.markdown(f'<div class="check {status}">{icon} {escape(label)}</div>',
                            unsafe_allow_html=True)
            st.caption("Real servers return a generic 401 to clients and log the specific reason.")

    with st.expander("Key management (rotation and revocation)"):
        ids = store.key_ids()
        st.write("Active key IDs: " + (", ".join(ids) if ids else "none"))
        k1, k2 = st.columns(2)
        if k1.button("Create new key"):
            n = 1
            while f"key-{n}" in ids:
                n += 1
            store.create_key(f"key-{n}")
            st.rerun()
        if ids:
            to_revoke = k2.selectbox("Revoke key", ids, key="revoke_sel")
            if k2.button("Revoke selected key"):
                store.revoke(to_revoke)
                st.rerun()

# --------------------------------------------------------------------------- attacks
with tab_attack:
    st.subheader("Attack scenarios")
    st.caption("Runs on a fresh server with random keys. PASS means the server behaved as expected.")
    if st.button("Run all scenarios", type="primary"):
        st.session_state["scenarios"] = hs.run_scenarios()
    rows = st.session_state.get("scenarios")
    if rows:
        passed = sum(r.passed for r in rows)
        (st.success if passed == len(rows) else st.error)(f"{passed} of {len(rows)} scenarios passed.")
        for r in rows:
            with st.container(border=True):
                st.markdown(f"**{'PASS' if r.passed else 'FAIL'}** - {r.name}")
                st.caption(r.description)
                st.markdown(f"Expected `{r.expected}`, got `{r.actual}`")
