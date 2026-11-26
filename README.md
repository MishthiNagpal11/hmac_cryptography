# HMAC-Based Message Authentication System

## Objective

Develop a sender-receiver application that creates and verifies an HMAC for a message using a shared secret key (Activity 18: HMAC and Message Authentication).

## Technologies used

Python, Streamlit, `hmac`, `hashlib` (HMAC-SHA256, `hmac.compare_digest()`).

## Install dependencies

```bash
pip install -r requirements.txt
```

## Run the application

```bash
streamlit run app.py
```

## Test the four verification scenarios

In the app: enter a message and a key in **Sender**, then open **Receiver and HMAC Verification** and select **Run the four scenarios**.

By hand:
1. **Sender**: enter a message and key, select **Generate HMAC**.
2. **Receiver**: select **Load message and tag from Sender**, enter the same key, select **Verify**.
3. Edit the message, the key, or one character of the tag, and select **Verify** again.

Automated:

```bash
python -m unittest tests -v
```

## Expected output

| Scenario | Result |
|---|---|
| Original message, correct key | Verification successful |
| Modified message, original tag | Verification unsuccessful |
| Original message, incorrect key | Verification unsuccessful |
| Original message, modified tag | Verification unsuccessful |

The **Plain Hash vs HMAC** tab shows a 64-character SHA-256 hash and a different 64-character HMAC-SHA256 for the same message.
