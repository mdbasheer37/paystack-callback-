
# app.py
import os
import json
import hmac
import hashlib
import uuid
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional

import requests
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from dotenv import load_dotenv
import jwt
from threading import Lock

# Load env
load_dotenv()

# ------------------------------
# Configuration
# ------------------------------
class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-this-secret")
    JWT_SECRET = os.getenv("JWT_SECRET", "change-jwt-secret")
    JWT_ALGORITHM = "HS256"
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    # Firebase
    FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL", "")
    FIREBASE_CREDENTIALS = os.getenv("FIREBASE_CREDENTIALS", "")  # JSON string

    # Paystack
    PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
    PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY", "")
    PAYSTACK_BASE_URL = "https://api.paystack.co"

    # VTPass
    VTPASS_API_KEY = os.getenv("VTPASS_API_KEY", "")
    VTPASS_BASE_URL = "https://vtpass.com/api"

    # Termii
    TERMII_API_KEY = os.getenv("TERMII_API_KEY", "")

    # App settings
    MIN_FUNDING = int(os.getenv("MIN_FUNDING", "100"))
    MAX_FUNDING = int(os.getenv("MAX_FUNDING", "500000"))

    # Admin emails (comma separated)
    ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "admin@cheap4u.com").split(",")

# ------------------------------
# Simple in-memory rate limit (per-ip)
# ------------------------------
rate_lock = Lock()
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
rate_store: Dict[str, Dict[str, Any]] = {}  # ip -> {count, reset_ts}

def rate_limit():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = int(time.time())
            with rate_lock:
                rec = rate_store.get(ip)
                if not rec or rec["reset_ts"] < now:
                    rec = {"count": 0, "reset_ts": now + 60}
                rec["count"] += 1
                rate_store[ip] = rec
                if rec["count"] > RATE_LIMIT:
                    return jsonify({"status": "error", "message": "Rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ------------------------------
# Utilities
# ------------------------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def gen_ref_code(user_id: str) -> str:
    import random, string
    base = (user_id[:4].upper() if len(user_id) >= 4 else user_id.upper())
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"REF{base}{random_part}"

def validate_email(email: str) -> bool:
    import re
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(email and re.match(pattern, email))

def validate_phone(phone: str) -> bool:
    return bool(phone and len(phone) == 11 and phone.isdigit() and phone.startswith(("070","080","081","090","091")))

def validate_amount(value) -> Optional[float]:
    try:
        a = float(value)
        if a <= 0:
            return None
        return a
    except:
        return None

# ------------------------------
# Simplified Firebase client (real + mock)
# ------------------------------
try:
    import firebase_admin
    from firebase_admin import credentials, db, auth as fb_auth
    FIREBASE_AVAILABLE = True
except Exception:
    FIREBASE_AVAILABLE = False

class FirebaseClient:
    def __init__(self):
        self.root = None
        self.mock = False
        self.mock_users = {}
        self.mock_transactions = {}
        self.mock_profit_wallet = {"total_available": 0.0, "total_earned": 0.0, "total_withdrawn": 0.0, "transaction_count": 0}
        if FIREBASE_AVAILABLE and Config.FIREBASE_CREDENTIALS:
            try:
                cred_dict = json.loads(Config.FIREBASE_CREDENTIALS)
                cred = credentials.Certificate(cred_dict)
                if not firebase_admin._apps:
                    firebase_admin.initialize_app(cred, {"databaseURL": Config.FIREBASE_DB_URL})
                self.root = db.reference("/")
            except Exception as e:
                print("Firebase init failed, using mock:", e)
                self.mock = True
        else:
            self.mock = True

    # User functions
    def create_user(self, user_data: Dict[str, Any]) -> (bool, str):
        user_id = f"user_{int(time.time()*1000)}"
        user_data = {**user_data, "created_at": now_iso()}
        if self.root:
            ref = self.root.child("users").push(user_data)
            return True, ref.key
        else:
            self.mock_users[user_id] = user_data
            return True, user_id

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        if self.root:
            users = self.root.child("users").get() or {}
            for uid, u in users.items():
                if u.get("email") == email.lower():
                    u["id"] = uid
                    return u
            return None
        else:
            for uid,u in self.mock_users.items():
                if u.get("email") == email.lower():
                    u["id"] = uid
                    return u
            return None

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        if self.root:
            data = self.root.child(f"users/{user_id}").get()
            if data:
                data["id"] = user_id
            return data
        else:
            u = self.mock_users.get(user_id)
            if u:
                u["id"] = user_id
            return u

    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        if self.root:
            self.root.child(f"users/{user_id}").update({**updates, "updated_at": now_iso()})
            return True
        else:
            if user_id in self.mock_users:
                self.mock_users[user_id].update(updates)
                return True
            return False

    # Wallet
    def update_user_wallet(self, user_id: str, amount_delta: float) -> bool:
        user = self.get_user(user_id)
        if not user:
            return False
        bal = float(user.get("wallet_balance", 0.0))
        new_bal = bal + float(amount_delta)
        if new_bal < 0:
            return False
        return self.update_user(user_id, {"wallet_balance": new_bal})

    # Transactions
    def create_transaction(self, tx: Dict[str, Any]) -> str:
        tx_id = f"tx_{int(time.time()*1000)}"
        tx["created_at"] = now_iso()
        if self.root:
            ref = self.root.child("transactions").push(tx)
            return ref.key
        else:
            self.mock_transactions[tx_id] = tx
            return tx_id

    def get_transaction_by_reference(self, ref_str: str) -> Optional[Dict[str, Any]]:
        if self.root:
            txs = self.root.child("transactions").get() or {}
            for tid, t in txs.items():
                if t.get("payment_reference") == ref_str:
                    t["id"] = tid
                    return t
            return None
        else:
            for tid, t in self.mock_transactions.items():
                if t.get("payment_reference") == ref_str:
                    t["id"] = tid
                    return t
            return None

    def update_transaction(self, tx_id: str, updates: Dict[str, Any]) -> bool:
        if self.root:
            self.root.child(f"transactions/{tx_id}").update(updates)
            return True
        else:
            if tx_id in self.mock_transactions:
                self.mock_transactions[tx_id].update(updates)
                return True
            return False

    # Profit wallet
    def update_profit_wallet(self, amount: float, transaction_type: str = "profit") -> bool:
        if self.root:
            ref = self.root.child("profit_wallet")
            data = ref.get() or {"total_available":0.0,"total_earned":0.0,"total_withdrawn":0.0,"transaction_count":0}
            if transaction_type == "profit":
                data["total_available"] = float(data.get("total_available",0)) + amount
                data["total_earned"] = float(data.get("total_earned",0)) + amount
                data["transaction_count"] = int(data.get("transaction_count",0)) + 1
            elif transaction_type == "withdraw":
                data["total_available"] = float(data.get("total_available",0)) - amount
                data["total_withdrawn"] = float(data.get("total_withdrawn",0)) + amount
            data["last_updated"] = now_iso()
            ref.set(data)
            return True
        else:
            if transaction_type == "profit":
                self.mock_profit_wallet["total_available"] += amount
                self.mock_profit_wallet["total_earned"] += amount
                self.mock_profit_wallet["transaction_count"] += 1
            elif transaction_type == "withdraw":
                self.mock_profit_wallet["total_available"] -= amount
                self.mock_profit_wallet["total_withdrawn"] += amount
            return True

firebase_client = FirebaseClient()

# ------------------------------
# Paystack wrapper
# ------------------------------
class PaystackService:
    def __init__(self):
        self.secret = Config.PAYSTACK_SECRET_KEY
        self.base = Config.PAYSTACK_BASE_URL
        self.headers = {"Authorization": f"Bearer {self.secret}"}

    def initialize_transaction(self, email: str, amount_naira: float, metadata: Dict = None, callback_url: str = None):
        url = f"{self.base}/transaction/initialize"
        payload = {
            "email": email,
            "amount": int(round(amount_naira * 100)),  # kobo
            "currency": "NGN",
            "metadata": metadata or {}
        }
        if callback_url:
            payload["callback_url"] = callback_url
        r = requests.post(url, json=payload, headers=self.headers, timeout=30)
        return r.json()

    def verify_transaction(self, reference: str):
        url = f"{self.base}/transaction/verify/{reference}"
        r = requests.get(url, headers=self.headers, timeout=30)
        return r.json()

paystack = PaystackService()

# ------------------------------
# VTPass wrapper (simple)
# ------------------------------
class VTPassService:
    def __init__(self):
        self.api_key = Config.VTPASS_API_KEY
        self.base = Config.VTPASS_BASE_URL
        self.headers = {"apiKey": self.api_key, "Content-Type": "application/json"}

    def pay(self, service_id, billers_code, variation_code, amount, phone=None):
        payload = {
            "serviceID": service_id,
            "billersCode": billers_code,
            "variation_code": variation_code,
            "amount": amount
        }
        if phone:
            payload["phone"] = phone
        url = f"{self.base}/pay"
        try:
            r = requests.post(url, headers=self.headers, json=payload, timeout=30)
            return r.json()
        except Exception as e:
            return {"code":"099","response_description":str(e)}

    def verify_service(self, service_id, billers_code):
        payload = {"serviceID": service_id, "billersCode": billers_code}
        url = f"{self.base}/merchant-verify"
        r = requests.post(url, headers=self.headers, json=payload, timeout=30)
        return r.json()

vtpass = VTPassService()

# ------------------------------
# Termii wrapper (OTP)
# ------------------------------
class TermiiService:
    def __init__(self):
        self.api_key = Config.TERMII_API_KEY
        self.base = "https://api.ng.termii.com/api"

    def send_sms(self, phone, message, sender_id="Cheap4uApp"):
        if not self.api_key:
            return {"status": "error", "message": "Termii API key not configured"}
        payload = {"to": phone, "from": sender_id, "sms": message, "type": "plain", "channel": "generic", "api_key": self.api_key}
        try:
            r = requests.post(f"{self.base}/sms/send", json=payload, timeout=20)
            return r.json()
        except Exception as e:
            return {"status": "error", "message": str(e)}

termii = TermiiService()

# ------------------------------
# JWT helpers
# ------------------------------
def create_jwt(payload: Dict[str, Any], exp_minutes=60*24*7):
    data = {**payload, "exp": datetime.utcnow() + timedelta(minutes=exp_minutes)}
    token = jwt.encode(data, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
    return token

def decode_jwt(token: str):
    try:
        data = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
        return data
    except Exception:
        return None

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"status":"error","message":"Authorization token required"}), 401
        token = header.split(" ",1)[1]
        data = decode_jwt(token)
        if not data:
            return jsonify({"status":"error","message":"Invalid or expired token"}), 401
        request.user = data
        return f(*args, **kwargs)
    return wrapper

# ------------------------------
# Flask app init
# ------------------------------
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ------------------------------
# Load data plans (shared JSON file)
# ------------------------------
DATA_PLANS_FILE = os.getenv("DATA_PLANS_FILE", "data_plans.json")
if os.path.exists(DATA_PLANS_FILE):
    with open(DATA_PLANS_FILE, "r") as f:
        DATA_PLANS = json.load(f)
else:
    DATA_PLANS = {}

# ------------------------------
# Helper: get plan id from name (Kivy calls same)
# ------------------------------
def get_plan_id_for_network(network, selected_plan_name):
    # DATA_PLANS structure: { "MTN": [ { "name":"1GB", "variation_code":"mtn-1gb", "variation_amount":... }, ... ], ... }
    plans = DATA_PLANS.get(network, [])
    for p in plans:
        if p.get("name") == selected_plan_name or p.get("variation_code") == selected_plan_name:
            return p.get("variation_code")
    return selected_plan_name

# ------------------------------
# AUTH ROUTES
# ------------------------------
@app.route("/api/auth/register", methods=["POST"])
@rate_limit()
def register():
    body = request.get_json(force=True)
    name = body.get("name","").strip()
    email = body.get("email","").strip().lower()
    phone = body.get("phone","").strip()
    password = body.get("password","")
    referral = body.get("referral_code")

    if not name or not email or not phone or not password:
        return jsonify({"status":"error","message":"Missing required fields"}), 400
    if not validate_email(email):
        return jsonify({"status":"error","message":"Invalid email"}), 400
    if not validate_phone(phone):
        return jsonify({"status":"error","message":"Invalid phone number"}), 400
    if len(password) < 6:
        return jsonify({"status":"error","message":"Password too short"}), 400
    existing = firebase_client.get_user_by_email(email)
    if existing:
        return jsonify({"status":"error","message":"Email already registered"}), 400

    # Create user record (unverified)
    pw_hash = hash_password(password)
    user_obj = {"name":name, "email":email, "phone":phone, "password_hash":pw_hash,
                "wallet_balance":0.0, "referral_balance":0.0, "is_verified":False}
    ok, user_id = firebase_client.create_user(user_obj)
    if not ok:
        return jsonify({"status":"error","message":"Failed to create user"}), 500

    # Generate referral code
    ref_code = gen_ref_code(user_id)
    firebase_client.update_user(user_id, {"referral_code": ref_code})

    # Save referral link if provided
    if referral:
        ref_user = firebase_client.get_user_by_email(referral) if "@" in referral else firebase_client.get_user_by_email(referral)
        # If referral code matches existing user's referral_code
        ref_owner = None
        if not ref_user:
            # try by referral code
            # iterate mock / real
            if firebase_client.root:
                users = firebase_client.root.child("users").get() or {}
                for uid, u in users.items():
                    if u.get("referral_code") == referral:
                        ref_owner = {"id": uid, **u}
                        break
            else:
                for uid,u in firebase_client.mock_users.items():
                    if u.get("referral_code") == referral:
                        ref_owner = {"id": uid, **u}
                        break
        else:
            ref_owner = ref_user

        if ref_owner:
            # create referral transaction record (pending until first successful transaction)
            firebase_client.create_transaction({"type": "referral_signup", "referrer_id": ref_owner["id"], "referred_id": user_id, "created_at": now_iso(), "status":"pending"})

    # Generate OTP and send via Termii
    otp_code = str(int(time.time()))[-6:]  # simple, replace with random if desired
    # store OTP in user record (expires)
    firebase_client.update_user(user_id, {"otp_code": otp_code, "otp_expires_at": (datetime.utcnow()+timedelta(minutes=10)).isoformat()})
    # Send SMS
    termii.send_sms(phone, f"Your verification code is {otp_code}. It expires in 10 minutes.", sender_id="Cheap4uApp")

    return jsonify({"status":"success","message":"User created. OTP sent","data":{"user_id":user_id,"email":email}}), 201

@app.route("/api/auth/login", methods=["POST"])
@rate_limit()
def login():
    body = request.get_json(force=True)
    email = body.get("email","").lower().strip()
    password = body.get("password","")
    if not validate_email(email) or not password:
        return jsonify({"status":"error","message":"Invalid credentials"}), 400
    user = firebase_client.get_user_by_email(email)
    if not user:
        return jsonify({"status":"error","message":"Account does not exist"}), 404
    if user.get("password_hash") != hash_password(password):
        return jsonify({"status":"error","message":"Incorrect password"}), 401
    if not user.get("is_verified", False):
        return jsonify({"status":"error","message":"Account requires verification","requires_verification":True,"user_id":user.get("id")}), 200

    token = create_jwt({"user_id": user.get("id"), "email":user.get("email")})
    return jsonify({"status":"success","message":"Login successful","data":{"user":user,"session_token":token}}), 200

@app.route("/api/auth/verify-otp", methods=["POST"])
@rate_limit()
def verify_otp():
    body = request.get_json(force=True)
    user_id = body.get("user_id")
    otp = body.get("otp_code") or body.get("otp")
    if not user_id or not otp:
        return jsonify({"status":"error","message":"Missing parameters"}), 400
    user = firebase_client.get_user(user_id)
    if not user:
        return jsonify({"status":"error","message":"User not found"}), 404
    # Check expiry
    expires = user.get("otp_expires_at")
    if not expires or datetime.fromisoformat(expires) < datetime.utcnow():
        return jsonify({"status":"error","message":"OTP expired"}), 400
    if user.get("otp_code") != otp:
        return jsonify({"status":"error","message":"Invalid OTP"}), 400
    # Mark verified
    firebase_client.update_user(user_id, {"is_verified": True, "otp_code": None, "otp_expires_at": None})
    token = create_jwt({"user_id": user_id, "email": user.get("email")})
    return jsonify({"status":"success","message":"Account verified","data":{"user": firebase_client.get_user(user_id), "session_token": token}}), 200

@app.route("/api/auth/resend-otp", methods=["POST"])
@rate_limit()
def resend_otp():
    body = request.get_json(force=True)
    user_id = body.get("user_id")
    if not user_id:
        return jsonify({"status":"error","message":"Missing user_id"}), 400
    user = firebase_client.get_user(user_id)
    if not user:
        return jsonify({"status":"error","message":"User not found"}), 404
    otp_code = str(int(time.time()))[-6:]
    firebase_client.update_user(user_id, {"otp_code": otp_code, "otp_expires_at": (datetime.utcnow()+timedelta(minutes=10)).isoformat()})
    termii.send_sms(user.get("phone"), f"Your verification code is {otp_code}. It expires in 10 minutes.", sender_id="Cheap4uApp")
    return jsonify({"status":"success","message":"OTP resent"}), 200

# ------------------------------
# Wallet / Payment
# ------------------------------
@app.route("/api/user/wallet", methods=["GET"])
@auth_required
@rate_limit()
def get_wallet():
    user_id = request.user.get("user_id")
    user = firebase_client.get_user(user_id)
    if not user:
        return jsonify({"status":"error","message":"User not found"}), 404
    data = {
        "main_balance": float(user.get("wallet_balance", 0.0)),
        "referral_balance": float(user.get("referral_balance", 0.0)),
        "profit_wallet": firebase_client.get_user_by_email("profit_wallet")  # not per-user
    }
    return jsonify({"status":"success","data":data}), 200

@app.route("/api/payment/initialize", methods=["POST"])
@rate_limit()
def initialize_payment():
    body = request.get_json(force=True)
    email = body.get("email")
    amount = validate_amount(body.get("amount"))
    if not email or not amount:
        return jsonify({"status":"error","message":"invalid payload"}), 400
    if amount < Config.MIN_FUNDING or amount > Config.MAX_FUNDING:
        return jsonify({"status":"error","message":"amount out of bounds"}), 400
    metadata = body.get("metadata", {})
    metadata["timestamp"] = now_iso()
    result = paystack.initialize_transaction(email, amount, metadata=metadata, callback_url=body.get("callback_url"))
    if not result.get("status"):
        return jsonify({"status":"error","message": result.get("message","Paystack init failed")}), 400
    # store transaction
    tx = {
        "user_email": email,
        "amount": amount,
        "payment_reference": result["data"]["reference"],
        "authorization_url": result["data"]["authorization_url"],
        "status": "pending",
        "type": body.get("service_type","wallet_funding"),
        "metadata": metadata
    }
    tx_id = firebase_client.create_transaction(tx)
    return jsonify({"status":"success","message":"initialized","data":{"reference": result["data"]["reference"], "authorization_url": result["data"]["authorization_url"], "transaction_id": tx_id}}), 200

@app.route("/api/payment/verify/<reference>", methods=["GET"])
@rate_limit()
def verify_payment(reference):
    if not reference:
        return jsonify({"status":"error","message":"Missing reference"}), 400
    # ensure idempotency: if we already marked transaction success, return
    tx = firebase_client.get_transaction_by_reference(reference)
    if tx and tx.get("status") == "success":
        return jsonify({"status":"success","message":"Already verified","data":tx}), 200
    result = paystack.verify_transaction(reference)
    if not result.get("status"):
        # failure
        return jsonify({"status":"error","message": result.get("message","verification failed")}), 400
    data = result.get("data", {})
    status = data.get("status")
    email = data.get("customer", {}).get("email") or (tx.get("user_email") if tx else None)
    amount_kobo = data.get("amount", 0)
    amount_naira = amount_kobo / 100.0
    if status == "success":
        # credit wallet and record tx
        # find transaction and update
        if not tx:
            tx_id = firebase_client.create_transaction({"user_email": email, "amount": amount_naira, "payment_reference": reference, "status": "success", "type":"wallet_funding", "created_at": now_iso()})
        else:
            tx_id = tx.get("id")
            firebase_client.update_transaction(tx_id, {"status":"success", "paystack_verify": data})
        # credit user
        if email:
            user = firebase_client.get_user_by_email(email)
            if user:
                firebase_client.update_user_wallet(user["id"], amount_naira)
        # profit for processing fee (small markup)
        profit = max(1.0, round(amount_naira * 0.015, 2))
        firebase_client.update_profit_wallet(profit)
        return jsonify({"status":"success","message":"Payment verified","data": {"amount": amount_naira, "reference": reference}}), 200
    else:
        # pending or failed
        if tx:
            firebase_client.update_transaction(tx.get("id"), {"status": status, "paystack_verify": data})
        return jsonify({"status":"error","message":"Payment not successful", "detail": status}), 400

# ------------------------------
# VTUPASS SERVICES
# ------------------------------
@app.route("/api/services/providers/<service_type>", methods=["GET"])
@rate_limit()
def get_providers(service_type):
    # return supported providers mapping (from config or file)
    # We'll return a static mapping (could be extended)
    providers = {
        "airtime": ["MTN", "Airtel", "Glo", "9Mobile"],
        "data": ["MTN", "Airtel", "Glo", "9Mobile"],
        "electricity": ["IKEDC", "EKEDC", "IBEDC", "AEDC"],
        "cable": ["DSTV", "GOTV", "Startimes", "Showmax"],
        "exam-pins": ["WAEC","NECO","JAMB","NABTEB"]
    }
    return jsonify({"status":"success","data": providers.get(service_type, [])}), 200

@app.route("/api/services/data/plans/<network>", methods=["GET"])
@rate_limit()
def get_data_plans(network):
    plans = DATA_PLANS.get(network)
    if plans is None:
        return jsonify({"status":"error","message":"Network not supported"}), 404
    return jsonify({"status":"success","data":plans}), 200

# Utility for handling VTPass response + profit + ledger
def handle_vtpass_purchase(service_type, request_data):
    # request_data must contain: user_email, service_id, billers_code, variation_code, amount
    user_email = request_data.get("user_email")
    base_amount = float(request_data.get("base_amount"))
    variation_code = request_data.get("variation_code")
    service_id = request_data.get("service_id")
    billers_code = request_data.get("billers_code")
    # Selling price: for simplicity we use percentage markup map
    markup_map = {"airtime":0.05, "data":0.10, "electricity":0.05, "cable":0.08, "exam_pins":0.15}
    markup = markup_map.get(service_type, 0.08)
    selling = round(base_amount * (1+markup), 2)
    min_profit = {"airtime":5,"data":10,"electricity":10,"cable":20,"exam_pins":50}
    profit = selling - base_amount
    if profit < min_profit.get(service_type, 0):
        profit = min_profit.get(service_type,0)
        selling = base_amount + profit
    # Deduct from user's wallet
    if user_email:
        user = firebase_client.get_user_by_email(user_email)
        if not user:
            return {"status":"error","message":"User not found"}, 404
        if float(user.get("wallet_balance",0)) < selling:
            return {"status":"error","message":"Insufficient wallet balance"}, 400
        ok = firebase_client.update_user_wallet(user["id"], -selling)
        if not ok:
            return {"status":"error","message":"Failed to debit wallet"}, 500
    # Call VTPass with base price
    vt_response = vtpass.pay(service_id, billers_code, variation_code, base_amount, phone=request_data.get("phone"))
    # VTPass success code is often '000' or code==0 depending on API; handle generically
    code = vt_response.get("code") or vt_response.get("response_code") or ""
    if vt_response.get("response_description") and ("insufficient" in vt_response.get("response_description").lower()):
        # refund the user
        if user_email and user:
            firebase_client.update_user_wallet(user["id"], base_amount)  # refund base; selling had been deducted but we refund only base here - adjust if you prefer full refund
        return {"status":"error","message":"VTPass error: " + vt_response.get("response_description")}, 400
    # on success:
    firebase_client.update_profit_wallet(profit)
    tx = {
        "user_email": user_email,
        "type": service_type,
        "service_id": service_id,
        "billers_code": billers_code,
        "variation_code": variation_code,
        "base_amount": base_amount,
        "selling_amount": selling,
        "profit_amount": profit,
        "status": "success",
        "vtpass_response": vt_response
    }
    txid = firebase_client.create_transaction(tx)
    # create ledger entry
    firebase_client.create_transaction({"type":"profit_ledger", "transaction_id": txid, "profit": profit, "created_at": now_iso()})
    return {"status":"success","message":"Purchase successful","data":{"txid":txid,"profit":profit,"vtpass":vt_response}}, 200

# Airtime
@app.route("/api/services/airtime", methods=["POST"])
@auth_required
@rate_limit()
def purchase_airtime():
    body = request.get_json(force=True)
    user_email = request.user.get("email")
    network = body.get("network")
    phone = body.get("phone")
    amount = validate_amount(body.get("amount"))
    if not (network and phone and amount):
        return jsonify({"status":"error","message":"Missing params"}), 400
    # Determine vtpass service id & variation code from mapping
    mapping = {"MTN":"mtn", "Airtel":"airtel","Glo":"glo","9Mobile":"etisalat"}
    service_id = mapping.get(network)
    if not service_id:
        return jsonify({"status":"error","message":"Unsupported network"}), 400
    request_data = {"user_email": user_email, "service_id": service_id, "billers_code": phone, "variation_code": f"{network.lower()}-{int(amount)}", "base_amount": amount, "phone": phone}
    result, status = handle_vtpass_purchase("airtime", request_data)
    return jsonify(result), status

# Data
@app.route("/api/services/data", methods=["POST"])
@auth_required
@rate_limit()
def purchase_data():
    body = request.get_json(force=True)
    user_email = request.user.get("email")
    network = body.get("network")
    phone = body.get("phone")
    plan_id = body.get("plan_id")  # expecting variation_code from data_plans.json
    # find plan base price
    plans = DATA_PLANS.get(network, [])
    plan = next((p for p in plans if p.get("variation_code")==plan_id), None)
    if not plan:
        return jsonify({"status":"error","message":"Invalid plan"}), 400
    base_amount = float(plan.get("variation_amount"))
    service_id = {"MTN":"mtn-data","Airtel":"airtel-data","Glo":"glo-data","9Mobile":"etisalat-data"}.get(network)
    request_data = {"user_email": user_email, "service_id": service_id, "billers_code": phone, "variation_code": plan_id, "base_amount": base_amount, "phone": phone}
    result, status = handle_vtpass_purchase("data", request_data)
    return jsonify(result), status

# Electricity
@app.route("/api/services/electricity", methods=["POST"])
@auth_required
@rate_limit()
def purchase_electricity():
    body = request.get_json(force=True)
    user_email = request.user.get("email")
    disco = body.get("disco")
    meter_number = body.get("meter_number")
    meter_type = body.get("meter_type","prepaid")
    amount = validate_amount(body.get("amount"))
    if not (disco and meter_number and amount):
        return jsonify({"status":"error","message":"Missing params"}), 400
    service_map = {"IKEDC":"ikeja-electric","EKEDC":"eko-electric","IBEDC":"ibadan-electric","AEDC":"abuja-electric"}
    service_id = service_map.get(disco)
    if not service_id:
        return jsonify({"status":"error","message":"Unsupported disco"}), 400
    request_data = {"user_email": user_email, "service_id": service_id, "billers_code": meter_number, "variation_code": meter_type, "base_amount": amount, "phone": body.get("phone")}
    result, status = handle_vtpass_purchase("electricity", request_data)
    return jsonify(result), status

# Cable
@app.route("/api/services/cable", methods=["POST"])
@auth_required
@rate_limit()
def purchase_cable():
    body = request.get_json(force=True)
    user_email = request.user.get("email")
    provider = body.get("provider")
    package_id = body.get("package_id")
    smartcard = body.get("smartcard")
    # base_amount from body or package lookup (not covered here)
    amount = validate_amount(body.get("amount"))
    if not (provider and package_id and smartcard and amount):
        return jsonify({"status":"error","message":"Missing params"}), 400
    service_map = {"DSTV":"dstv","GOTV":"gotv","Startimes":"startimes","Showmax":"showmax"}
    service_id = service_map.get(provider)
    if not service_id:
        return jsonify({"status":"error","message":"Unsupported provider"}), 400
    request_data = {"user_email": user_email, "service_id": service_id, "billers_code": smartcard, "variation_code": package_id, "base_amount": amount, "phone": body.get("phone")}
    result, status = handle_vtpass_purchase("cable", request_data)
    return jsonify(result), status

# Exam pins
@app.route("/api/services/exam-pin", methods=["POST"])
@auth_required
@rate_limit()
def purchase_exam_pin():
    body = request.get_json(force=True)
    user_email = request.user.get("user_email") or request.user.get("email")
    exam_type = body.get("exam_type")
    quantity = int(body.get("quantity", 1))
    exam_prices = {"WAEC":3500,"NECO":3500,"JAMB":5000,"NABTEB":3500}
    if exam_type not in exam_prices:
        return jsonify({"status":"error","message":"Invalid exam type"}), 400
    base_amount = exam_prices[exam_type] * quantity
    request_data = {"user_email": user_email, "service_id": exam_type.lower(), "billers_code": "", "variation_code": exam_type, "base_amount": base_amount}
    result, status = handle_vtpass_purchase("exam_pins", request_data)
    return jsonify(result), status

# ------------------------------
# Referrals endpoints
# ------------------------------
@app.route("/api/user/referrals", methods=["GET"])
@auth_required
@rate_limit()
def get_user_referrals():
    user_id = request.user.get("user_id")
    # fetch referral transactions
    if firebase_client.root:
        all_refs = firebase_client.root.child("referral_transactions").get() or {}
        out = []
        for rid, r in all_refs.items():
            if r.get("referrer_id") == user_id:
                out.append({**r, "id":rid})
    else:
        out = []
        for rid, r in getattr(firebase_client, "mock_referral_transactions", {}).items():
            if r.get("referrer_id") == user_id:
                out.append({**r, "id":rid})
    return jsonify({"status":"success","data":out}), 200

# ------------------------------
# Admin profit withdrawal
# ------------------------------
@app.route("/api/admin/profit/withdraw", methods=["POST"])
@rate_limit()
def admin_profit_withdraw():
    email = request.args.get("user_email") or request.get_json().get("user_email")
    if not email or email not in Config.ADMIN_EMAILS:
        return jsonify({"status":"error","message":"Admin required"}), 403
    body = request.get_json(force=True)
    amount = validate_amount(body.get("amount"))
    if not amount:
        return jsonify({"status":"error","message":"Invalid amount"}), 400
    # check profit wallet
    profit_data = firebase_client.get_profit_data() if hasattr(firebase_client,"get_profit_data") else firebase_client.mock_profit_wallet
    available = float(profit_data.get("total_available", 0))
    if amount > available:
        return jsonify({"status":"error","message":"Insufficient profit balance"}), 400
    # create mock transfer (implement paystack transfer in production)
    firebase_client.update_profit_wallet(amount, transaction_type="withdraw")
    # record withdrawal
    firebase_client.create_transaction({"type":"profit_withdrawal", "amount": amount, "admin_email": email, "status":"completed"})
    return jsonify({"status":"success","message":"Withdrawal completed","data":{"amount": amount}}), 200

# ------------------------------
# Health & misc
# ------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok","time": now_iso()}), 200

# ------------------------------
# Error handlers
# ------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status":"error","message":"Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status":"error","message":"Internal server error"}), 500

# ------------------------------
# Run
# ------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT","10000"))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
