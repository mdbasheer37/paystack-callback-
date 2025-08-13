import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hashlib
import hmac
import json

# Load environment variables (for local testing)
load_dotenv()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

app = Flask(__name__)

# ======= Redirect Callback =======
@app.route("/payment/redirect")
def payment_redirect():
    reference = request.args.get("reference")
    return f"Payment completed! Reference: {reference}. We will confirm it shortly."

# ======= Webhook Notification =======
@app.route("/paystack/callback", methods=["POST"])
def paystack_webhook():
    # Verify Paystack Signature
    signature = request.headers.get("x-paystack-signature")
    body = request.get_data()

    computed_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        body,
        hashlib.sha512
    ).hexdigest()

    if signature != computed_signature:
        return "Invalid signature", 400

    data = json.loads(body)
    print("✅ Webhook received:", data)

    # You can add database update logic here

    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000) 
