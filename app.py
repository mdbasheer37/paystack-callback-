import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hashlib
import hmac
import json
from datetime import datetime

# Load environment variables
load_dotenv()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///payments.db")

app = Flask(__name__)

# In-memory database (replace with actual database in production)
transactions = {}

# ======= Payment Initialization =======
@app.route("/payment/initialize", methods=["POST"])
def initialize_payment():
    """
    Initialize a Paystack payment transaction
    Expects JSON with: email, amount, metadata (optional)
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ["email", "amount"]):
            return jsonify({"error": "Missing required fields"}), 400
            
        # Create transaction record
        transaction_id = f"tx_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        transaction = {
            "id": transaction_id,
            "email": data["email"],
            "amount": data["amount"],
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "metadata": data.get("metadata", {})
        }
        
        transactions[transaction_id] = transaction
        
        # In a real app, you would call Paystack API here to initialize payment
        # For demo, we'll return a mock response
        response = {
            "status": True,
            "message": "Authorization URL created",
            "data": {
                "authorization_url": f"https://paystack.com/pay/{transaction_id}",
                "access_code": f"code_{transaction_id}",
                "reference": transaction_id
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ======= Redirect Callback =======
@app.route("/payment/redirect")
def payment_redirect():
    """
    Handle Paystack redirect after payment
    """
    reference = request.args.get("reference")
    if not reference:
        return "Missing reference parameter", 400
    
    # Verify transaction status (in real app, verify with Paystack API)
    transaction = transactions.get(reference, {})
    
    if transaction.get("status") == "success":
        return f"Payment completed successfully! Reference: {reference}"
    else:
        return f"Payment processing... Reference: {reference}. We will confirm it shortly."

# ======= Webhook Notification =======
@app.route("/paystack/callback", methods=["POST"])
def paystack_webhook():
    """
    Handle Paystack webhook notifications
    """
    try:
        # Verify Paystack Signature
        signature = request.headers.get("x-paystack-signature")
        if not signature:
            return "Missing signature", 400

        body = request.get_data()
        computed_signature = hmac.new(
            PAYSTACK_SECRET_KEY.encode("utf-8"),
            body,
            hashlib.sha512
        ).hexdigest()

        if not hmac.compare_digest(signature, computed_signature):
            return "Invalid signature", 400

        data = json.loads(body)
        event = data.get("event")
        
        if event == "charge.success":
            # Handle successful payment
            transaction_ref = data["data"]["reference"]
            amount = data["data"]["amount"] / 100  # Convert from kobo to Naira
            
            # Update transaction status
            if transaction_ref in transactions:
                transactions[transaction_ref]["status"] = "success"
                transactions[transaction_ref]["paid_at"] = datetime.now().isoformat()
                
                # Here you would typically:
                # 1. Update user wallet balance
                # 2. Send confirmation email/SMS
                # 3. Log the transaction in your database
                
                print(f"✅ Payment successful for {transaction_ref}, Amount: ₦{amount:,.2f}")
            
            return jsonify({"status": "success"}), 200
            
        elif event in ["charge.failed", "charge.reversed"]:
            # Handle failed/reversed payments
            transaction_ref = data["data"]["reference"]
            
            if transaction_ref in transactions:
                transactions[transaction_ref]["status"] = "failed"
                print(f"❌ Payment failed for {transaction_ref}")
            
            return jsonify({"status": "received"}), 200
            
        else:
            return jsonify({"status": "ignored"}), 200
            
    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ======= Transaction Verification =======
@app.route("/payment/verify/<reference>", methods=["GET"])
def verify_payment(reference):
    """
    Verify a payment transaction status
    """
    # In a real app, you would verify with Paystack API
    transaction = transactions.get(reference, {})
    
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    
    return jsonify({
        "status": "success",
        "data": {
            "reference": reference,
            "status": transaction.get("status", "pending"),
            "amount": transaction.get("amount"),
            "email": transaction.get("email"),
            "metadata": transaction.get("metadata", {})
        }
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
