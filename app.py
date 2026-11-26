"""Streamlit app: HMAC-Based Message Authentication System (Activity 18).

Run: streamlit run app.py
"""

import streamlit as st

import crypto_utils as cu

st.set_page_config(page_title="HMAC Message Authentication", page_icon="🛡️", layout="centered")

# Dark navy theme with cyan/green accents (base colors are set in .streamlit/config.toml).
st.markdown(
    """
    <style>
    .block-container { padding-top: 4rem; max-width: 820px; }
    .app-header { border: 1px solid #1f3558; border-left: 4px solid #22d3ee; border-radius: 10px;
                  background: linear-gradient(135deg, #10203d 0%, #0b1426 80%);
                  padding: 1.1rem 1.4rem; margin-bottom: 1.2rem; }
    .app-header h1 { font-size: 1.7rem; margin: 0; padding: 0; color: #e6edf7; }
    .app-header p { margin: .3rem 0 0 0; color: #8da2c0; font-size: .95rem; }
    .app-header p span { color: #34d399; font-weight: 600; }
    h3 { color: #22d3ee; }
    .stTabs [data-baseweb="tab-list"] { gap: 6px; border-bottom: 1px solid #1f3558; }
    .stTabs [data-baseweb="tab"] { background: #101c33; border-radius: 8px 8px 0 0;
                                   padding: .5rem 1rem; color: #8da2c0; }
    .stTabs [aria-selected="true"] { background: #13213b; color: #22d3ee; }
    div[data-testid="stCode"] pre { border: 1px solid #1f3558; border-radius: 8px;
                                    background: #0a1120 !important; }
    div[data-testid="stCode"] code { color: #22d3ee !important; word-break: break-all;
                                     white-space: pre-wrap !important; }
    .stTextArea textarea, .stTextInput input { background: #0a1120; border: 1px solid #1f3558; }
    .stTextArea textarea:focus, .stTextInput input:focus { border-color: #22d3ee; }
    .stButton > button { border-radius: 8px; border: 1px solid #1f3558; }
    .stButton > button[kind="primary"] { background: #22d3ee; border-color: #22d3ee; color: #0b1426; font-weight: 600; }
    .stButton > button[kind="primary"]:hover { background: #34d399; border-color: #34d399; color: #0b1426; }
    div[data-testid="stAlert"] { border-radius: 8px; }
    </style>
    <div class="app-header">
      <h1>🛡️ HMAC-Based Message Authentication System</h1>
      <p>HMAC-SHA256 with a shared secret key <span>● ready</span></p>
    </div>
    """,
    unsafe_allow_html=True,
)


def load_from_sender() -> None:
    """Copy the sender's message and tag into the receiver (the key is NOT copied)."""
    result = st.session_state.get("sender_result")
    if result:
        st.session_state["rx_message"] = result["message"]
        st.session_state["rx_tag"] = result["tag"]


tab_sender, tab_receiver, tab_compare = st.tabs(
    ["Sender", "Receiver and HMAC Verification", "Plain Hash vs HMAC"]
)

# ----------------------------------------------------------------------------- Sender
with tab_sender:
    st.subheader("Sender")
    message = st.text_area("Message", key="tx_message")
    key = st.text_input("Shared secret key", type="password", key="tx_key")

    if st.button("Generate HMAC", type="primary"):
        try:
            st.session_state["sender_result"] = {
                "message": message,
                "tag": cu.generate_hmac(message, key),
            }
        except ValueError as exc:
            st.session_state.pop("sender_result", None)
            st.error(str(exc))

    result = st.session_state.get("sender_result")
    if result:
        st.write("Original message")
        st.code(result["message"], language=None)
        st.write("HMAC tag")
        st.code(result["tag"], language=None)

# --------------------------------------------------------------------------- Receiver
with tab_receiver:
    st.subheader("Receiver and HMAC Verification")
    st.button("Load message and tag from Sender", on_click=load_from_sender)
    rx_message = st.text_area("Received message", key="rx_message")
    rx_tag = st.text_input("Received HMAC tag", key="rx_tag")
    rx_key = st.text_input("Shared secret key", type="password", key="rx_key")

    if st.button("Verify", type="primary"):
        if not rx_message or not rx_tag or not rx_key:
            st.error("Enter the message, the HMAC tag, and the shared secret key.")
        else:
            ok, explanation = cu.verify_hmac(rx_message, rx_key, rx_tag)
            (st.success if ok else st.error)(explanation)
            if ok or len(rx_tag.strip()) == cu.TAG_HEX_LENGTH:
                try:
                    st.write("Calculated HMAC")
                    st.code(cu.generate_hmac(rx_message, rx_key), language=None)
                    st.write("Received HMAC")
                    st.code(rx_tag.strip(), language=None)
                except ValueError:
                    pass

    st.divider()
    st.subheader("Independent verification scenarios")
    st.caption("Uses the message and shared secret key entered in the Sender tab.")
    if st.button("Run the four scenarios"):
        try:
            rows = cu.run_four_scenarios(st.session_state.get("tx_message", ""),
                                         st.session_state.get("tx_key", ""))
            for name, expected, actual in rows:
                label = lambda s: "Verification successful" if s else "Verification unsuccessful"
                line = f"{name}: expected {label(expected)}, got {label(actual)}"
                (st.success if expected == actual else st.error)(
                    f"{'PASS' if expected == actual else 'FAIL'} - {line}"
                )
        except (ValueError, IndexError):
            st.error("Enter a message and a shared secret key in the Sender tab first.")

# ----------------------------------------------------------------------------- Compare
with tab_compare:
    st.subheader("Plain Hash vs HMAC")
    c_message = st.text_area("Message", key="cmp_message")
    c_key = st.text_input("Shared secret key", type="password", key="cmp_key")

    if st.button("Compare", type="primary"):
        try:
            st.write("Plain SHA-256 hash (no key)")
            st.code(cu.plain_sha256(c_message), language=None)
            st.write("HMAC-SHA256 (with shared secret key)")
            st.code(cu.generate_hmac(c_message, c_key), language=None)
            st.info(
                "A plain hash uses no secret, so anyone can compute it. An attacker can change "
                "the message and calculate a new valid hash, and the receiver cannot tell who "
                "created it. An HMAC can only be produced by someone who knows the shared secret key."
            )
        except ValueError as exc:
            st.error(str(exc))
