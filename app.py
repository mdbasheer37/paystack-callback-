import os
import json
import hmac
import hashlib
import requests
import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import re
import uuid

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# ==================== CONFIGURATION ====================
class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Paystack
    PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
    PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY')
    PAYSTACK_BASE_URL = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')
    
    # VTPass
    VTPASS_API_KEY = os.getenv('VTPASS_API_KEY')
    VTPASS_BASE_URL = os.getenv('VTPASS_BASE_URL', 'https://vtpass.com/api')
    
    # Firebase
    FIREBASE_CREDENTIALS_JSON = os.getenv('FIREBASE_CREDENTIALS_JSON')
    FIREBASE_DB_URL = os.getenv('FIREBASE_DB_URL')
    
    # Admin
    ADMIN_API_KEY = os.getenv('ADMIN_API_KEY')

# ==================== ENHANCED FIREBASE CLIENT ====================
class FirebaseClient:
    _instance = None
    
    def __init__(self):
        try:
            if not firebase_admin._apps:
                # Try multiple ways to get credentials
                cred = None
                
                # Method 1: JSON string from environment
                if os.getenv('FIREBASE_CREDENTIALS_JSON'):
                    try:
                        cred_json = json.loads(os.getenv('FIREBASE_CREDENTIALS_JSON'))
                        cred = credentials.Certificate(cred_json)
                        print("✅ Firebase credentials loaded from environment variable")
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse FIREBASE_CREDENTIALS_JSON: {e}")
                
                # Method 2: File path from environment
                elif os.getenv('FIREBASE_CREDENTIALS_PATH') and os.path.exists(os.getenv('FIREBASE_CREDENTIALS_PATH')):
                    try:
                        cred = credentials.Certificate(os.getenv('FIREBASE_CREDENTIALS_PATH'))
                        print("✅ Firebase credentials loaded from file path")
                    except Exception as e:
                        print(f"❌ Failed to load Firebase credentials from file: {e}")
                
                # Method 3: Default credentials (for development)
                else:
                    try:
                        cred = credentials.ApplicationDefault()
                        print("✅ Using default Firebase credentials")
                    except Exception as e:
                        print(f"❌ No Firebase credentials available: {e}")
                        self.root_ref = None
                        return
                
                if cred:
                    firebase_admin.initialize_app(cred, {
                        'databaseURL': os.getenv('FIREBASE_DB_URL', 'https://your-project-default-rtdb.firebaseio.com/')
                    })
                    self.root_ref = db.reference('/')
                    print("✅ Firebase initialized successfully")
                else:
                    print("❌ No valid Firebase credentials found")
                    self.root_ref = None
            else:
                self.root_ref = db.reference('/')
                print("✅ Firebase already initialized")
            
        except Exception as e:
            print(f"❌ Firebase initialization failed: {str(e)}")
            self.root_ref = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def create_user(self, user_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Create a new user and return (success, user_id)"""
        if not self.root_ref:
            # Fallback: generate mock user ID
            mock_id = f"mock_{int(datetime.now().timestamp())}"
            print(f"⚠️ Firebase not available, using mock user: {mock_id}")
            return True, mock_id
        
        try:
            # Check if user already exists
            existing_user = self.get_user_by_email(user_data.get('email', ''))
            if existing_user:
                return False, "User with this email already exists"
            
            # Add timestamps
            user_data['created_at'] = {'.sv': 'timestamp'}
            user_data['updated_at'] = {'.sv': 'timestamp'}
            
            # Create user
            user_ref = self.root_ref.child('users').push(user_data)
            user_id = user_ref.key
            
            print(f"✅ User created successfully: {user_id}")
            return True, user_id
            
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            return False, str(e)
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        if not self.root_ref:
            return None
        user_ref = self.root_ref.child(f'users/{user_id}')
        return user_ref.get()
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        if not self.root_ref:
            return None
        users_ref = self.root_ref.child('users')
        users = users_ref.get()
        
        if users:
            for user_id, user_data in users.items():
                if user_data.get('email') == email:
                    return {**user_data, 'id': user_id}
        return None
    
    def update_user_wallet(self, user_id: str, amount: float) -> bool:
        if not self.root_ref:
            return True
        try:
            user_ref = self.root_ref.child(f'users/{user_id}/wallet_balance')
            current_balance = user_ref.get() or 0
            user_ref.set(float(current_balance) + amount)
            return True
        except Exception:
            return False
    
    def create_transaction(self, transaction_data: Dict[str, Any]) -> str:
        if not self.root_ref:
            return "mock_tx_id"
        transaction_ref = self.root_ref.child('transactions').push(transaction_data)
        return transaction_ref.key
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        if not self.root_ref:
            return None
        transaction_ref = self.root_ref.child(f'transactions/{transaction_id}')
        return transaction_ref.get()
    
    def get_transaction_by_reference(self, reference: str) -> Optional[Dict[str, Any]]:
        if not self.root_ref:
            return None
        transactions_ref = self.root_ref.child('transactions')
        transactions = transactions_ref.get()
        
        if transactions:
            for tx_id, tx_data in transactions.items():
                if tx_data.get('payment_reference') == reference:
                    return {**tx_data, 'id': tx_id}
        return None
    
    def update_profit_wallet(self, amount: float) -> bool:
        if not self.root_ref:
            return True
        try:
            profit_ref = self.root_ref.child('profit_wallet/total_available')
            current_profit = profit_ref.get() or 0
            profit_ref.set(float(current_profit) + amount)
            return True
        except Exception:
            return False
    
    def create_profit_ledger_entry(self, ledger_data: Dict[str, Any]) -> str:
        if not self.root_ref:
            return "mock_ledger_id"
        ledger_ref = self.root_ref.child('profit_ledger').push(ledger_data)
        return ledger_ref.key
    
    def get_profit_ledger_entries(self, status: str = None) -> Dict[str, Any]:
        if not self.root_ref:
            return {}
        ledger_ref = self.root_ref.child('profit_ledger')
        entries = ledger_ref.get() or {}
        
        if status:
            return {k: v for k, v in entries.items() if v.get('status') == status}
        return entries
    
    def create_recipient(self, recipient_data: Dict[str, Any]) -> str:
        if not self.root_ref:
            return "mock_recipient_id"
        recipient_ref = self.root_ref.child('recipients').push(recipient_data)
        return recipient_ref.key
    
    def get_recipient(self, recipient_code: str) -> Optional[Dict[str, Any]]:
        if not self.root_ref:
            return None
        recipients_ref = self.root_ref.child('recipients')
        recipients = recipients_ref.get()
        
        if recipients:
            for rec_id, rec_data in recipients.items():
                if rec_data.get('recipient_code') == recipient_code:
                    return {**rec_data, 'id': rec_id}
        return None

# ==================== PAYSTACK SERVICE ====================
class PaystackService:
    def __init__(self):
        self.secret_key = os.getenv('PAYSTACK_SECRET_KEY')
        self.base_url = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')
        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }
    
    def initialize_transaction(self, email: str, amount: int, channel: str = None, metadata: Dict = None) -> Dict[str, Any]:
        url = f"{self.base_url}/transaction/initialize"
        
        payload = {
            'email': email,
            'amount': amount * 100,
            'metadata': metadata or {}
        }
        
        if channel:
            payload['channels'] = [channel]
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': str(e)}
    
    def create_dedicated_account(self, email: str, amount: int = None) -> Dict[str, Any]:
        url = f"{self.base_url}/dedicated_account"
        
        payload = {
            'email': email,
            'first_name': email.split('@')[0]
        }
        
        if amount:
            payload['amount'] = amount * 100
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': str(e)}
    
    def verify_transaction(self, reference: str) -> Dict[str, Any]:
        url = f"{self.base_url}/transaction/verify/{reference}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': str(e)}
    
    def create_transfer_recipient(self, account_number: str, bank_code: str, account_name: str) -> Dict[str, Any]:
        url = f"{self.base_url}/transferrecipient"
        
        payload = {
            'type': 'nuban',
            'name': account_name,
            'account_number': account_number,
            'bank_code': bank_code,
            'currency': 'NGN'
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': str(e)}
    
    def initiate_transfer(self, recipient: str, amount: int, reason: str = "Profit withdrawal") -> Dict[str, Any]:
        url = f"{self.base_url}/transfer"
        
        payload = {
            'source': 'balance',
            'amount': amount * 100,
            'recipient': recipient,
            'reason': reason
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': str(e)}
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        computed_signature = hmac.new(
            self.secret_key.encode('utf-8'),
            payload,
            hashlib.sha512
        ).hexdigest()
        
        return hmac.compare_digest(computed_signature, signature)

# ==================== VTPASS SERVICE ====================
class VTPassService:
    def __init__(self):
        self.api_key = os.getenv('VTPASS_API_KEY')
        self.base_url = os.getenv('VTPASS_BASE_URL', 'https://vtpass.com/api')
        self.headers = {
            'api-key': self.api_key,
            'secret-key': self.api_key,
            'Content-Type': 'application/json'
        }
    
    def pay(self, service_id: str, billers_code: str, variation_code: str,
           amount: int, phone: str = None, request_id: str = None) -> Dict[str, Any]:
        url = f"{self.base_url}/pay"
        
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code,
            'variation_code': variation_code,
            'amount': amount,
            'phone': phone,
            'request_id': request_id or f"req_{int(datetime.now().timestamp())}"
        }
        
        payload = {k: v for k, v in payload.items() if v is not None}
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'code': '099', 'response_description': str(e)}
    
    def verify_smartcard(self, service_id: str, billers_code: str) -> Dict[str, Any]:
        url = f"{self.base_url}/merchant-verify"
        
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'code': '099', 'response_description': str(e)}
    
    def get_service_variations(self, service_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/service-variations"
        
        params = {'serviceID': service_id}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'code': '099', 'response_description': str(e)}

# ==================== VALIDATION UTILITIES ====================
def validate_email(email: str) -> bool:
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def validate_phone(phone: str) -> bool:
    return len(phone) == 11 and phone.isdigit()

def validate_amount(amount: Any) -> Tuple[bool, float]:
    try:
        amount_float = float(amount)
        if amount_float <= 0:
            return False, 0
        return True, amount_float
    except (ValueError, TypeError):
        return False, 0

def validate_payment_request(data: Dict[str, Any]) -> Tuple[bool, str]:
    if not data.get('email'):
        return False, "Email is required"
    
    if not validate_email(data['email']):
        return False, "Invalid email format"
    
    if not data.get('amount'):
        return False, "Amount is required"
    
    valid, amount = validate_amount(data['amount'])
    if not valid:
        return False, "Invalid amount"
    
    if amount < 100:
        return False, "Amount must be at least ₦100"
    
    return True, ""

def validate_vtpass_request(data: Dict[str, Any]) -> Tuple[bool, str]:
    required_fields = ['serviceID', 'billersCode', 'variation_code', 'amount']
    
    for field in required_fields:
        if not data.get(field):
            return False, f"{field} is required"
    
    valid, amount = validate_amount(data['amount'])
    if not valid:
        return False, "Invalid amount"
    
    return True, ""

# ==================== FLASK APP ====================
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize services
firebase_client = FirebaseClient.get_instance()
paystack_service = PaystackService()
vtpass_service = VTPassService()

print("🚀 VTU Backend Services Initialized!")

# ==================== ROUTES ====================

@app.route('/')
def home():
    return jsonify({
        'message': 'VTU Backend API is running! 🚀',
        'status': 'active',
        'timestamp': datetime.now().isoformat(),
        'endpoints': {
            'health': 'GET /health',
            'register': 'POST /api/auth/register',
            'login': 'POST /api/auth/login',
            'payment_initialize': 'POST /api/payment/initialize',
            'virtual_account': 'POST /api/payment/virtual-account',
            'verify_payment': 'GET /api/payment/verify/<reference>',
            'paystack_webhook': 'POST /api/payment/webhook/paystack',
            'vtpass_pay': 'POST /api/vtpass/pay',
            'vtpass_verify': 'POST /api/vtpass/verify',
            'admin_withdraw': 'POST /api/admin/withdraw'
        }
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'VTU Backend API',
        'timestamp': datetime.now().isoformat(),
        'firebase': 'connected' if firebase_client.root_ref else 'disconnected'
    })

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Register a new user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'status': 'error', 'message': f'{field} is required'}), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Validate phone
        if not validate_phone(data['phone']):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400
        
        # Check if user already exists
        existing_user = firebase_client.get_user_by_email(data['email'])
        if existing_user:
            return jsonify({'status': 'error', 'message': 'User with this email already exists'}), 400
        
        # Hash password
        hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
        
        # Create user data
        user_data = {
            'name': data['name'],
            'email': data['email'].lower(),
            'phone': data['phone'],
            'password': hashed_password,
            'wallet_balance': 0.0,
            'referral_balance': 0.0,
            'is_verified': False,
            'is_premium': False,
            'joined_date': datetime.now().strftime("%Y-%m-%d"),
            'last_login': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'created_at': {'.sv': 'timestamp'},
            'updated_at': {'.sv': 'timestamp'}
        }
        
        # Create user in Firebase
        success, result = firebase_client.create_user(user_data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'User registered successfully',
                'data': {
                    'user_id': result,
                    'email': data['email'],
                    'name': data['name']
                }
            })
        else:
            return jsonify({'status': 'error', 'message': result}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """Login user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        # Validate required fields
        if not data.get('email') or not data.get('password'):
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Find user by email
        user = firebase_client.get_user_by_email(data['email'])
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Verify password
        hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
        if user.get('password') != hashed_password:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Update last login
        if firebase_client.root_ref:
            firebase_client.root_ref.child(f'users/{user["id"]}').update({
                'last_login': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'updated_at': {'.sv': 'timestamp'}
            })
        
        # Return user data (excluding password)
        user_response = {k: v for k, v in user.items() if k != 'password'}
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': user_response
        })
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}'}), 500

# ==================== PAYMENT ROUTES ====================

@app.route('/api/payment/initialize', methods=['POST'])
def initialize_payment():
    """Initialize Paystack payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        is_valid, error_msg = validate_payment_request(data)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error_msg}), 400
        
        channel = data.get('channel', 'card')
        metadata = data.get('metadata', {})
        
        result = paystack_service.initialize_transaction(
            email=data['email'],
            amount=int(data['amount']),
            channel=channel,
            metadata=metadata
        )
        
        if result.get('status'):
            # Store transaction in Firebase
            tx_data = {
                'user_email': data['email'],
                'amount': float(data['amount']),
                'channel': channel,
                'payment_reference': result['data']['reference'],
                'status': 'pending',
                'type': 'wallet_funding',
                'created_at': {'.sv': 'timestamp'},
                'metadata': metadata
            }
            
            tx_id = firebase_client.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'data': {
                    **result['data'],
                    'transaction_id': tx_id
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Payment initialization failed')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/payment/virtual-account', methods=['POST'])
def create_virtual_account():
    """Create dedicated virtual account"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('email'):
            return jsonify({'status': 'error', 'message': 'Email is required'}), 400
        
        if not validate_email(data['email']):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        amount = data.get('amount')
        
        result = paystack_service.create_dedicated_account(
            email=data['email'],
            amount=int(amount) if amount else None
        )
        
        if result.get('status'):
            account_data = result['data']
            
            # Store virtual account details
            va_data = {
                'user_email': data['email'],
                'account_number': account_data.get('account_number'),
                'account_name': account_data.get('account_name'),
                'bank': account_data.get('bank', {}).get('name'),
                'reference': account_data.get('reference'),
                'expires_at': account_data.get('expires_at'),
                'created_at': {'.sv': 'timestamp'}
            }
            
            va_id = firebase_client.create_transaction(va_data)
            
            return jsonify({
                'status': 'success',
                'data': {
                    **account_data,
                    'virtual_account_id': va_id
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Virtual account creation failed')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/payment/verify/<reference>', methods=['GET'])
def verify_payment(reference):
    """Verify payment status"""
    try:
        if not reference:
            return jsonify({'status': 'error', 'message': 'Reference is required'}), 400
        
        # Check Firebase first
        existing_tx = firebase_client.get_transaction_by_reference(reference)
        
        if existing_tx and existing_tx.get('status') == 'success':
            return jsonify({
                'status': 'success',
                'data': existing_tx,
                'from_cache': True
            })
        
        # Verify with Paystack
        result = paystack_service.verify_transaction(reference)
        
        if result.get('status') and result['data']['status'] == 'success':
            # Update transaction in Firebase
            tx_update = {
                'status': 'success',
                'verified_at': {'.sv': 'timestamp'},
                'paystack_response': result['data']
            }
            
            # Credit user wallet if this is a funding transaction
            if existing_tx and existing_tx.get('type') == 'wallet_funding':
                user_email = existing_tx.get('user_email')
                amount = result['data']['amount'] / 100
                
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    firebase_client.update_user_wallet(user['id'], amount)
            
            return jsonify({
                'status': 'success',
                'data': result['data']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Payment verification failed')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/payment/webhook/paystack', methods=['POST'])
def paystack_webhook():
    """Handle Paystack webhooks"""
    try:
        payload = request.get_data()
        signature = request.headers.get('x-paystack-signature')
        
        if not paystack_service.verify_webhook_signature(payload, signature):
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 400
        
        webhook_data = request.get_json()
        event = webhook_data.get('event')
        
        if event == 'charge.success':
            data = webhook_data.get('data', {})
            reference = data.get('reference')
            amount = data.get('amount', 0) / 100
            
            # Update transaction in Firebase
            existing_tx = firebase_client.get_transaction_by_reference(reference)
            
            if existing_tx:
                tx_update = {
                    'status': 'success',
                    'webhook_processed_at': {'.sv': 'timestamp'},
                    'paystack_webhook_data': webhook_data
                }
                
                # Credit user wallet for funding transactions
                if existing_tx.get('type') == 'wallet_funding':
                    user_email = existing_tx.get('user_email')
                    user = firebase_client.get_user_by_email(user_email)
                    if user:
                        firebase_client.update_user_wallet(user['id'], amount)
                        print(f"💰 Credited {amount} to user {user_email}")
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Webhook error: {str(e)}'}), 500

# ==================== VTPASS ROUTES ====================

@app.route('/api/vtpass/pay', methods=['POST'])
def vtpass_pay():
    """Process VTPass payment with profit tracking"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        is_valid, error_msg = validate_vtpass_request(data)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error_msg}), 400
        
        selling_price = float(data['amount'])
        vendor_price = data.get('vendor_price')
        profit_amount = data.get('profit')
        
        # Calculate profit
        if profit_amount is None:
            if vendor_price is not None:
                profit_amount = selling_price - float(vendor_price)
            else:
                profit_amount = selling_price * 0.1  # Default 10% profit
        
        if profit_amount < 0:
            return jsonify({'status': 'error', 'message': 'Invalid profit calculation'}), 400
        
        # Check user wallet if user_email provided
        user_email = data.get('user_email')
        
        if user_email:
            user = firebase_client.get_user_by_email(user_email)
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
            if user.get('wallet_balance', 0) < selling_price:
                return jsonify({'status': 'error', 'message': 'Insufficient wallet balance'}), 400
            
            # Deduct from wallet
            firebase_client.update_user_wallet(user['id'], -selling_price)
        
        # Make VTPass payment
        result = vtpass_service.pay(
            service_id=data['serviceID'],
            billers_code=data['billersCode'],
            variation_code=data['variation_code'],
            amount=selling_price,
            phone=data.get('phone'),
            request_id=data.get('request_id')
        )
        
        # Record transaction
        tx_data = {
            'user_email': user_email,
            'type': 'vtpass_purchase',
            'service_id': data['serviceID'],
            'billers_code': data['billersCode'],
            'variation_code': data['variation_code'],
            'amount': selling_price,
            'vendor_amount': vendor_price,
            'profit': profit_amount,
            'status': 'success' if result.get('code') == '000' else 'failed',
            'vtpass_response': result,
            'created_at': {'.sv': 'timestamp'}
        }
        
        tx_id = firebase_client.create_transaction(tx_data)
        
        if result.get('code') == '000':  # VTPass success code
            # Add to profit wallet
            firebase_client.update_profit_wallet(profit_amount)
            
            # Record profit ledger entry
            ledger_data = {
                'transaction_id': tx_id,
                'amount': profit_amount,
                'status': 'available',
                'created_at': {'.sv': 'timestamp'}
            }
            
            firebase_client.create_profit_ledger_entry(ledger_data)
            
            return jsonify({
                'status': 'success',
                'data': {
                    **result,
                    'transaction_id': tx_id,
                    'profit_amount': profit_amount
                }
            })
        else:
            # Refund user wallet if payment failed
            if user_email and user:
                firebase_client.update_user_wallet(user['id'], selling_price)
            
            return jsonify({
                'status': 'error',
                'message': result.get('response_description', 'VTPass payment failed'),
                'data': result
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/vtpass/verify', methods=['POST'])
def verify_service():
    """Verify service (smartcard, meter, etc.)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('serviceID') or not data.get('billersCode'):
            return jsonify({'status': 'error', 'message': 'serviceID and billersCode are required'}), 400
        
        result = vtpass_service.verify_smartcard(
            service_id=data['serviceID'],
            billers_code=data['billersCode']
        )
        
        if result.get('code') == '000':
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('response_description', 'Verification failed')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

# ==================== USER PROFILE ROUTES ====================

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get user profile by email"""
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'status': 'error', 'message': 'Email parameter is required'}), 400
        
        if not validate_email(email):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        user = firebase_client.get_user_by_email(email)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Remove password from response
        user_response = {k: v for k, v in user.items() if k != 'password'}
        
        return jsonify({
            'status': 'success',
            'data': user_response
        })
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to get user profile: {str(e)}'}), 500

@app.route('/api/user/update-wallet', methods=['POST'])
def update_user_wallet():
    """Update user wallet balance"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('user_id') or not data.get('amount'):
            return jsonify({'status': 'error', 'message': 'user_id and amount are required'}), 400
        
        valid, amount = validate_amount(data['amount'])
        if not valid:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        
        success = firebase_client.update_user_wallet(data['user_id'], amount)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Wallet updated successfully',
                'data': {
                    'user_id': data['user_id'],
                    'amount': amount
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Failed to update wallet'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to update wallet: {str(e)}'}), 500

# ==================== ADMIN ROUTES ====================

def require_admin_auth():
    """Check admin authentication"""
    admin_key = request.headers.get('X-Admin-API-Key') or (request.get_json() or {}).get('admin_api_key')
    
    if not admin_key or admin_key != os.getenv('ADMIN_API_KEY'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    return None

@app.route('/api/admin/withdraw', methods=['POST'])
def admin_withdraw():
    """Admin profit withdrawal"""
    try:
        auth_error = require_admin_auth()
        if auth_error:
            return auth_error
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('recipient_account') and not data.get('recipient_bank_code'):
            return jsonify({'status': 'error', 'message': 'recipient_account or recipient_bank_code is required'}), 400
        
        if not data.get('amount'):
            return jsonify({'status': 'error', 'message': 'amount is required'}), 400
        
        valid, amount = validate_amount(data['amount'])
        if not valid:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        
        # Check profit wallet balance
        profit_wallet = firebase_client.root_ref.child('profit_wallet/total_available').get() or 0 if firebase_client.root_ref else 0
        
        if amount > profit_wallet:
            return jsonify({'status': 'error', 'message': 'Insufficient profit balance'}), 400
        
        # Create or get transfer recipient
        recipient_code = data.get('recipient_code')
        
        if not recipient_code:
            recipient_result = paystack_service.create_transfer_recipient(
                account_number=data['recipient_account'],
                bank_code=data['recipient_bank_code'],
                account_name=data.get('recipient_name', 'Profit Withdrawal')
            )
            
            if not recipient_result.get('status'):
                return jsonify({
                    'status': 'error',
                    'message': recipient_result.get('message', 'Recipient creation failed')
                }), 400
            
            recipient_code = recipient_result['data']['recipient_code']
            
            # Store recipient in Firebase
            recipient_data = {
                'recipient_code': recipient_code,
                'bank_code': data['recipient_bank_code'],
                'account_number': data['recipient_account'],
                'account_name': recipient_result['data']['name'],
                'created_at': {'.sv': 'timestamp'}
            }
            
            firebase_client.create_recipient(recipient_data)
        
        # Initiate transfer
        transfer_result = paystack_service.initiate_transfer(
            recipient=recipient_code,
            amount=amount,
            reason=data.get('narration', 'Profit withdrawal')
        )
        
        if transfer_result.get('status'):
            # Update profit wallet
            firebase_client.update_profit_wallet(-amount)
            
            # Update profit ledger entries
            if firebase_client.root_ref:
                ledger_entries = firebase_client.get_profit_ledger_entries(status='available')
                
                remaining_amount = amount
                for ledger_id, entry in ledger_entries.items():
                    if remaining_amount <= 0:
                        break
                    
                    entry_amount = entry.get('amount', 0)
                    if entry_amount <= remaining_amount:
                        firebase_client.root_ref.child(f'profit_ledger/{ledger_id}').update({
                            'status': 'withdrawn',
                            'withdrawn_at': {'.sv': 'timestamp'},
                            'withdraw_tx_ref': transfer_result['data']['reference']
                        })
                        remaining_amount -= entry_amount
                    else:
                        firebase_client.root_ref.child(f'profit_ledger/{ledger_id}').update({
                            'amount': entry_amount - remaining_amount
                        })
                        
                        withdrawn_data = {
                            'transaction_id': entry.get('transaction_id'),
                            'amount': remaining_amount,
                            'status': 'withdrawn',
                            'created_at': entry.get('created_at'),
                            'withdrawn_at': {'.sv': 'timestamp'},
                            'withdraw_tx_ref': transfer_result['data']['reference']
                        }
                        
                        firebase_client.create_profit_ledger_entry(withdrawn_data)
                        remaining_amount = 0
            
            return jsonify({
                'status': 'success',
                'data': {
                    'transfer_reference': transfer_result['data']['reference'],
                    'amount': amount,
                    'recipient': recipient_code
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': transfer_result.get('message', 'Transfer failed')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405

# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    print(f"🚀 Starting VTU Backend on port {port}")
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
