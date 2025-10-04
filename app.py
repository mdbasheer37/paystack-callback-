import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hashlib
import hmac
import json
import requests
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db
from functools import wraps

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

# Initialize Firebase
firebase_initialized = False
try:
    if os.getenv("FIREBASE_CREDENTIALS_JSON"):
        cred_dict = json.loads(os.getenv("FIREBASE_CREDENTIALS_JSON"))
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
        firebase_initialized = True
        print("✅ Firebase initialized successfully")
    else:
        print("❌ Firebase credentials not found")
except Exception as e:
    print(f"❌ Firebase initialization failed: {str(e)}")

# Payment methods
PAYMENT_METHODS = {
    "card": {"name": "Card", "icon": "credit-card", "color": "#3498db"},
    "transfer": {"name": "Bank Transfer", "icon": "bank", "color": "#2ecc71"},
    "ussd": {"name": "USSD", "icon": "phone", "color": "#e74c3c"}
}

# ======= DECORATORS =======
def require_firebase(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not firebase_initialized:
            return jsonify({"error": "Database not available"}), 503
        return func(*args, **kwargs)
    return wrapper

# ======= UTILITY FUNCTIONS =======
def verify_paystack_signature(signature, body):
    """Verify Paystack webhook signature"""
    if not PAYSTACK_SECRET_KEY:
        return False
    computed_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(signature, computed_signature)

@require_firebase
def log_transaction_to_firebase(transaction_data):
    """Log transaction to Firebase Realtime Database"""
    try:
        ref = db.reference('transactions')
        new_transaction_ref = ref.push()
        new_transaction_ref.set(transaction_data)
        return new_transaction_ref.key
    except Exception as e:
        print(f"❌ Error logging to Firebase: {str(e)}")
        return None

@require_firebase
def update_user_wallet(user_email, amount):
    """Update user's wallet balance in Firebase"""
    try:
        users_ref = db.reference('users')
        user_query = users_ref.order_by_child('email').equal_to(user_email).get()
        
        if user_query:
            user_key = list(user_query.keys())[0]
            current_balance = user_query[user_key].get('wallet_balance', 0)
            users_ref.child(user_key).update({
                'wallet_balance': current_balance + amount,
                'last_funding_date': datetime.now().isoformat()
            })
            return True
        return False
    except Exception as e:
        print(f"❌ Error updating user wallet: {str(e)}")
        return False

def initialize_paystack_transaction(email, amount, metadata=None, channel=None):
    """Initialize a transaction with Paystack"""
    if not PAYSTACK_SECRET_KEY:
        return {"error": "Paystack not configured"}

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "email": email,
        "amount": int(amount * 100),  # Paystack uses kobo (for NGN)
        "metadata": metadata or {},
        "callback_url": f"{os.getenv('BACKEND_URL')}/payment/redirect"
    }
    
    if channel:
        payload["channels"] = [channel]
        
    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Paystack initialization error: {str(e)}")
        return {"error": str(e)}

def create_dedicated_virtual_account(email, amount):
    """Create dedicated virtual account for bank transfer"""
    if not PAYSTACK_SECRET_KEY:
        return {"error": "Paystack not configured"}

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "customer": email,
        "preferred_bank": "wema-bank",
    }
    
    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/dedicated_account",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Paystack virtual account error: {str(e)}")
        return {"error": str(e)}

def verify_paystack_transaction(reference):
    """Verify a Paystack transaction"""
    if not PAYSTACK_SECRET_KEY:
        return {"error": "Paystack not configured"}

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(
            f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Paystack verification error: {str(e)}")
        return {"error": str(e)}

# ======= ROUTES =======
@app.route("/")
def index():
    return jsonify({
        "message": "Cheap4u VTU Payment Service API",
        "version": "1.0",
        "status": "active"
    })

@app.route("/api/payment/methods")
def get_payment_methods():
    """API endpoint to get available payment methods"""
    return jsonify({
        "status": "success",
        "data": PAYMENT_METHODS
    })

@app.route("/api/payment/initialize", methods=["POST"])
def api_initialize_payment():
    """API endpoint for mobile app to initialize payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        email = data.get("email")
        amount = data.get("amount")
        channel = data.get("channel", "card")
        service_type = data.get("service_type", "wallet_funding")
        
        if not email or not amount:
            return jsonify({"error": "Email and amount are required"}), 400
            
        try:
            amount = float(amount)
        except ValueError:
            return jsonify({"error": "Amount must be a number"}), 400

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
        
        if "error" in response:
            return jsonify({"error": response["error"]}), 500
            
        if not response or not response.get("status"):
            return jsonify({"error": "Payment initialization failed"}), 400

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
        
        transaction_id = log_transaction_to_firebase(transaction_data)
        
        return jsonify({
            "status": "success",
            "data": {
                "authorization_url": response["data"]["authorization_url"],
                "access_code": response["data"]["access_code"],
                "reference": response["data"]["reference"],
                "transaction_id": transaction_id
            }
        })
        
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/payment/virtual-account", methods=["POST"])
def api_create_virtual_account():
    """API endpoint to create dedicated virtual account"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        email = data.get("email")
        amount = data.get("amount")
        
        if not email or not amount:
            return jsonify({"error": "Email and amount are required"}), 400
            
        try:
            amount = float(amount)
        except ValueError:
            return jsonify({"error": "Amount must be a number"}), 400

        # Create dedicated virtual account
        response = create_dedicated_virtual_account(email, amount)
        
        if "error" in response:
            return jsonify({"error": response["error"]}), 500
            
        if not response or not response.get("status"):
            return jsonify({"error": "Virtual account creation failed"}), 400

        # Log transaction to Firebase
        transaction_data = {
            "email": email,
            "amount": amount,
            "service_type": "wallet_funding",
            "payment_method": "Bank Transfer",
            "status": "pending",
            "reference": response["data"].get("reference", ""),
            "account_details": response["data"],
            "created_at": datetime.now().isoformat()
        }
        
        transaction_id = log_transaction_to_firebase(transaction_data)
        
        return jsonify({
            "status": "success",
            "data": {
                "account_details": response["data"],
                "transaction_id": transaction_id
            }
        })
        
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/payment/verify/<reference>")
def api_verify_payment(reference):
    """API endpoint to verify a payment"""
    if not reference:
        return jsonify({"error": "Reference is required"}), 400

    # Verify the transaction
    verification = verify_paystack_transaction(reference)
    
    if "error" in verification:
        return jsonify({"error": verification["error"]}), 500
        
    if not verification or not verification.get("status"):
        return jsonify({
            "status": "error",
            "message": "Payment verification failed",
            "reference": reference
        }), 400

    # Update Firebase with payment status
    transaction_updated = False
    wallet_updated = False
    
    if firebase_initialized:
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
                transaction_updated = True
                
                # Update user wallet balance in Firebase
                if verification["data"]["status"] == "success":
                    user_email = verification["data"]["customer"]["email"]
                    amount = verification["data"]["amount"] / 100  # Convert back to Naira
                    wallet_updated = update_user_wallet(user_email, amount)
                    
        except Exception as e:
            print(f"❌ Error updating transaction: {str(e)}")

    return jsonify({
        "status": "success",
        "data": {
            "reference": reference,
            "payment_status": verification["data"]["status"],
            "amount": verification["data"]["amount"] / 100,
            "transaction_updated": transaction_updated,
            "wallet_updated": wallet_updated,
            "verification_data": verification["data"]
        }
    })

@app.route("/api/webhook/paystack", methods=["POST"])
def paystack_webhook():
    """Webhook endpoint for Paystack notifications"""
    # Verify Paystack Signature
    signature = request.headers.get("x-paystack-signature")
    if not signature:
        return "No signature provided", 400

    body = request.get_data()
    if not verify_paystack_signature(signature, body):
        return "Invalid signature", 400

    data = request.get_json()
    print("✅ Webhook received:", data.get("event"), data.get("data", {}).get("reference"))
    
    # Handle different webhook events
    event = data.get("event")
    
    if event == "charge.success":
        # Update transaction in Firebase
        reference = data["data"]["reference"]
        
        if firebase_initialized:
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
                        update_user_wallet(user_email, amount)
                        
                    print(f"✅ Transaction {reference} updated successfully via webhook")
                    
            except Exception as e:
                print(f"❌ Error updating transaction via webhook: {str(e)}")
                return jsonify({"status": "error", "message": str(e)}), 500
                
    return jsonify({"status": "success"}), 200

@app.route("/api/health")
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "firebase_initialized": firebase_initialized,
        "paystack_configured": bool(PAYSTACK_SECRET_KEY)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    debug = os.getenv("DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
