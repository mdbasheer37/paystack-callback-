
import os
from flask import Flask, request, jsonify, redirect, url_for
from dotenv import load_dotenv
import hashlib
import hmac
import json
import requests
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Paystack configuration
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
PAYSTACK_BASE_URL = "https://api.paystack.co"

# Firebase configuration
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
FIREBASE_CREDENTIALS = json.loads(os.getenv("FIREBASE_CREDENTIALS"))

# Initialize Firebase
cred = credentials.Certificate(FIREBASE_CREDENTIALS)
firebase_admin.initialize_app(cred, {
    'databaseURL': FIREBASE_DB_URL
})

# Payment methods
PAYMENT_METHODS = {
    "card": {
        "name": "Card",
        "icon": "credit-card",
        "color": "#3498db"
    },
    "bank_transfer": {
        "name": "Bank Transfer",
        "icon": "bank",
        "color": "#2ecc71"
    },
    "ussd": {
        "name": "USSD",
        "icon": "phone",
        "color": "#e74c3c"
    },
    "mobile_money": {
        "name": "Mobile Money",
        "icon": "mobile",
        "color": "#9b59b6"
    },
    "qr": {
        "name": "QR Code",
        "icon": "qrcode",
        "color": "#f39c12"
    }
}

# ======= UTILITY FUNCTIONS =======
def verify_paystack_signature(signature, body):
    computed_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        body,
        hashlib.sha512
    ).hexdigest()
    return signature == computed_signature

def log_transaction_to_firebase(transaction_data):
    try:
        ref = db.reference('transactions')
        new_transaction_ref = ref.push()
        new_transaction_ref.set(transaction_data)
        return new_transaction_ref.key
    except Exception as e:
        print(f"Error logging to Firebase: {str(e)}")
        return None

def initialize_paystack_transaction(email, amount, metadata=None, channel=None):
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "email": email,
        "amount": int(amount * 100),  # Paystack uses kobo (for NGN)
        "metadata": metadata or {},
        "callback_url": url_for('payment_redirect', _external=True)
    }
    
    if channel:
        payload["channels"] = [channel]
    
    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Paystack initialization error: {str(e)}")
        return None

def verify_paystack_transaction(reference):
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(
            f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Paystack verification error: {str(e)}")
        return None

# ======= ROUTES =======
@app.route("/")
def index():
    return """
    <h1>VTU Payment Service</h1>
    <p>Endpoints:</p>
    <ul>
        <li><a href="/fund">Fund Account</a></li>
        <li><a href="/payment/methods">Payment Methods</a></li>
    </ul>
    """

@app.route("/fund")
def fund_account():
    return """
    <h1>Fund Your Account</h1>
    <form action="/payment/initialize" method="post">
        <label>Email: <input type="email" name="email" required></label><br>
        <label>Amount (₦): <input type="number" name="amount" min="100" required></label><br>
        <label>Payment Method:
            <select name="channel">
                <option value="card">Card</option>
                <option value="bank_transfer">Bank Transfer</option>
                <option value="ussd">USSD</option>
                <option value="mobile_money">Mobile Money</option>
            </select>
        </label><br>
        <input type="hidden" name="service_type" value="wallet_funding">
        <button type="submit">Proceed to Payment</button>
    </form>
    """

@app.route("/payment/methods")
def payment_methods():
    methods_html = ""
    for method_id, method in PAYMENT_METHODS.items():
        methods_html += f"""
        <div style="border: 1px solid {method['color']}; padding: 10px; margin: 10px; border-radius: 5px;">
            <h3>{method['name']}</h3>
            <p>Icon: {method['icon']}</p>
            <a href="/fund?method={method_id}">Select this method</a>
        </div>
        """
    
    return f"""
    <h1>Available Payment Methods</h1>
    {methods_html}
    """

@app.route("/payment/initialize", methods=["POST"])
def initialize_payment():
    try:
        email = request.form.get("email")
        amount = float(request.form.get("amount"))
        channel = request.form.get("channel")
        service_type = request.form.get("service_type", "wallet_funding")
        
        # Initialize payment with Paystack
        metadata = {
            "service_type": service_type,
            "custom_fields": [
                {"display_name": "Funding Amount", "variable_name": "amount", "value": amount}
            ]
        }
        
        response = initialize_paystack_transaction(
            email=email,
            amount=amount,
            metadata=metadata,
            channel=channel
        )
        
        if not response or not response.get("status"):
            return "Payment initialization failed. Please try again.", 400
        
        # Log transaction to Firebase
        transaction_data = {
            "email": email,
            "amount": amount,
            "service_type": service_type,
            "payment_method": PAYMENT_METHODS.get(channel, {}).get("name", "Unknown"),
            "status": "initiated",
            "reference": response["data"]["reference"],
            "authorization_url": response["data"]["authorization_url"],
            "created_at": datetime.now().isoformat(),
            "metadata": metadata
        }
        
        log_transaction_to_firebase(transaction_data)
        
        # Redirect to payment page
        return redirect(response["data"]["authorization_url"])
    
    except Exception as e:
        return f"An error occurred: {str(e)}", 500

@app.route("/payment/redirect")
def payment_redirect():
    reference = request.args.get("reference")
    if not reference:
        return "Reference is required", 400
    
    # Verify the transaction
    verification = verify_paystack_transaction(reference)
    if not verification or not verification.get("status"):
        return """
        <h1>Payment Verification Failed</h1>
        <p>We couldn't verify your payment. Please contact support with reference: {reference}</p>
        <a href="/">Return Home</a>
        """
    
    # Update Firebase with payment status
    try:
        ref = db.reference('transactions')
        transactions = ref.order_by_child('reference').equal_to(reference).get()
        
        if transactions:
            transaction_key = list(transactions.keys())[0]
            ref.child(transaction_key).update({
                "status": verification["data"]["status"],
                "verified_at": datetime.now().isoformat(),
                "payment_details": verification["data"]
            })
            
            # Update user wallet balance in Firebase
            if verification["data"]["status"] == "success":
                user_email = verification["data"]["customer"]["email"]
                amount = verification["data"]["amount"] / 100  # Convert back to Naira
                
                # Update user's wallet balance
                users_ref = db.reference('users')
                user_query = users_ref.order_by_child('email').equal_to(user_email).get()
                
                if user_query:
                    user_key = list(user_query.keys())[0]
                    current_balance = user_query[user_key].get('wallet_balance', 0)
                    users_ref.child(user_key).update({
                        'wallet_balance': current_balance + amount,
                        'last_funding_date': datetime.now().isoformat()
                    })
            
            return f"""
            <h1>Payment Successful!</h1>
            <p>Reference: {reference}</p>
            <p>Amount: ₦{verification["data"]["amount"] / 100:,.2f}</p>
            <p>Your wallet has been credited successfully.</p>
            <a href="/">Return Home</a>
            """
    
    except Exception as e:
        print(f"Error updating transaction: {str(e)}")
    
    return f"""
    <h1>Payment Completed</h1>
    <p>Reference: {reference}. We will confirm it shortly.</p>
    <a href="/">Return Home</a>
    """

@app.route("/paystack/callback", methods=["POST"])
def paystack_webhook():
    # Verify Paystack Signature
    signature = request.headers.get("x-paystack-signature")
    if not signature:
        return "No signature provided", 400
    
    body = request.get_data()
    
    if not verify_paystack_signature(signature, body):
        return "Invalid signature", 400
    
    data = json.loads(body)
    print("✅ Webhook received:", data)
    
    # Handle different webhook events
    event = data.get("event")
    
    if event == "charge.success":
        # Update transaction in Firebase
        reference = data["data"]["reference"]
        try:
            ref = db.reference('transactions')
            transactions = ref.order_by_child('reference').equal_to(reference).get()
            
            if transactions:
                transaction_key = list(transactions.keys())[0]
                ref.child(transaction_key).update({
                    "status": "success",
                    "verified_at": datetime.now().isoformat(),
                    "payment_details": data["data"]
                })
                
                # Update user wallet balance
                if data["data"]["status"] == "success":
                    user_email = data["data"]["customer"]["email"]
                    amount = data["data"]["amount"] / 100
                    
                    users_ref = db.reference('users')
                    user_query = users_ref.order_by_child('email').equal_to(user_email).get()
                    
                    if user_query:
                        user_key = list(user_query.keys())[0]
                        current_balance = user_query[user_key].get('wallet_balance', 0)
                        users_ref.child(user_key).update({
                            'wallet_balance': current_balance + amount,
                            'last_funding_date': datetime.now().isoformat()
                        })
                
                print(f"Transaction {reference} updated successfully")
        except Exception as e:
            print(f"Error updating transaction: {str(e)}")
    
    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)))
