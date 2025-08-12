import os
from flask import Flask, request
from dotenv import load_dotenv

# Load environment variables when running locally
load_dotenv()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

app = Flask(__name__)

@app.route("/paystack/callback", methods=["POST", "GET"])
def paystack_callback():
    data = request.json or request.form.to_dict()
    print("✅ Payment callback received:", data)
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
