import os
import json
import hmac
import hashlib
import requests
import firebase_admin
from firebase_admin import credentials, db, auth
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import re
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("🚀 Starting VTU Backend Initialization...")

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
    
    # Termii
    TERMII_API_KEY = os.getenv('TERMII_API_KEY')
    
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
                cred = None
                
                # Method 1: JSON string from environment
                if os.getenv('FIREBASE_CREDENTIALS_JSON'):
                    try:
                        cred_json = json.loads(os.getenv('FIREBASE_CREDENTIALS_JSON'))
                        cred = credentials.Certificate(cred_json)
                        print("✅ Firebase credentials loaded from environment")
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse FIREBASE_CREDENTIALS_JSON: {e}")
                        # Create mock credentials for development
                        cred = credentials.Certificate({
                            "type": "service_account",
                            "project_id": "vtu-app-dev",
                            "private_key": "mock-key-for-dev",
                            "client_email": "mock@vtu-app-dev.iam.gserviceaccount.com"
                        })
                else:
                    # Use mock credentials for development
                    cred = credentials.Certificate({
                        "type": "service_account",
                        "project_id": "vtu-app-dev",
                        "private_key": "mock-key-for-dev",
                        "client_email": "mock@vtu-app-dev.iam.gserviceaccount.com"
                    })
                
                firebase_admin.initialize_app(cred, {
                    'databaseURL': os.getenv('FIREBASE_DB_URL', 'https://vtu-app-dev-default-rtdb.firebaseio.com/')
                })
                print("✅ Firebase initialized successfully")
            
            self.root_ref = db.reference('/')
            self._setup_default_data()
            
        except Exception as e:
            print(f"❌ Firebase initialization failed: {str(e)}")
            self.root_ref = None
    
    def _setup_default_data(self):
        """Initialize default data structure"""
        try:
            # Initialize profit wallet if not exists
            if self.root_ref.child('profit_wallet').get() is None:
                self.root_ref.child('profit_wallet').set({
                    'total_available': 0.0,
                    'total_earned': 0.0,
                    'last_updated': datetime.now().isoformat()
                })
                print("✅ Profit wallet initialized")
            
            # Initialize settings if not exists
            if self.root_ref.child('settings').get() is None:
                self.root_ref.child('settings').set({
                    'app_version': '1.0.0',
                    'maintenance_mode': False,
                    'min_funding_amount': 100,
                    'max_funding_amount': 500000
                })
                print("✅ Settings initialized")
                
        except Exception as e:
            print(f"⚠️ Default data setup warning: {e}")
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def create_user(self, user_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Create a new user"""
        try:
            # Check if user already exists
            existing_user = self.get_user_by_email(user_data.get('email', ''))
            if existing_user:
                return False, "User with this email already exists"
            
            # Add timestamps
            user_data['created_at'] = datetime.now().isoformat()
            user_data['updated_at'] = datetime.now().isoformat()
            user_data['last_login'] = datetime.now().isoformat()
            
            # Create user
            user_ref = self.root_ref.child('users').push(user_data)
            user_id = user_ref.key
            
            print(f"✅ User created: {user_id}")
            return True, user_id
            
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            return False, str(e)
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        if not self.root_ref:
            return self._get_mock_user(user_id)
        try:
            user_ref = self.root_ref.child(f'users/{user_id}')
            user_data = user_ref.get()
            if user_data:
                user_data['id'] = user_id
            return user_data
        except Exception as e:
            print(f"❌ Error getting user: {e}")
            return self._get_mock_user(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        if not self.root_ref:
            return self._get_mock_user_by_email(email)
        try:
            users_ref = self.root_ref.child('users')
            users = users_ref.get()
            
            if users:
                for user_id, user_data in users.items():
                    if user_data.get('email') == email.lower():
                        user_data['id'] = user_id
                        return user_data
            return None
        except Exception as e:
            print(f"❌ Error getting user by email: {e}")
            return self._get_mock_user_by_email(email)
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user data"""
        if not self.root_ref:
            return True
        try:
            updates['updated_at'] = datetime.now().isoformat()
            self.root_ref.child(f'users/{user_id}').update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating user: {e}")
            return False
    
    def update_user_wallet(self, user_id: str, amount: float) -> bool:
        """Update user wallet balance"""
        if not self.root_ref:
            return True
        try:
            user_ref = self.root_ref.child(f'users/{user_id}')
            user_data = user_ref.get() or {}
            
            current_balance = user_data.get('wallet_balance', 0.0)
            new_balance = max(0.0, float(current_balance) + amount)
            
            user_ref.update({
                'wallet_balance': new_balance,
                'updated_at': datetime.now().isoformat()
            })
            
            print(f"💰 Updated wallet for {user_id}: {current_balance} -> {new_balance}")
            return True
        except Exception as e:
            print(f"❌ Error updating wallet: {e}")
            return False
    
    def create_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """Create a transaction record"""
        if not self.root_ref:
            return f"mock_tx_{int(datetime.now().timestamp())}"
        try:
            transaction_data['created_at'] = datetime.now().isoformat()
            transaction_ref = self.root_ref.child('transactions').push(transaction_data)
            return transaction_ref.key
        except Exception as e:
            print(f"❌ Error creating transaction: {e}")
            return f"mock_tx_{int(datetime.now().timestamp())}"
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Get transaction by ID"""
        if not self.root_ref:
            return None
        try:
            transaction_ref = self.root_ref.child(f'transactions/{transaction_id}')
            tx_data = transaction_ref.get()
            if tx_data:
                tx_data['id'] = transaction_id
            return tx_data
        except Exception as e:
            print(f"❌ Error getting transaction: {e}")
            return None
    
    def get_transaction_by_reference(self, reference: str) -> Optional[Dict[str, Any]]:
        """Get transaction by payment reference"""
        if not self.root_ref:
            return None
        try:
            transactions_ref = self.root_ref.child('transactions')
            transactions = transactions_ref.get()
            
            if transactions:
                for tx_id, tx_data in transactions.items():
                    if tx_data.get('payment_reference') == reference:
                        tx_data['id'] = tx_id
                        return tx_data
            return None
        except Exception as e:
            print(f"❌ Error getting transaction by reference: {e}")
            return None
    
    def update_transaction(self, transaction_id: str, updates: Dict[str, Any]) -> bool:
        """Update transaction data"""
        if not self.root_ref:
            return True
        try:
            self.root_ref.child(f'transactions/{transaction_id}').update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating transaction: {e}")
            return False
    
    def update_profit_wallet(self, amount: float) -> bool:
        """Update profit wallet"""
        if not self.root_ref:
            return True
        try:
            profit_ref = self.root_ref.child('profit_wallet')
            current_data = profit_ref.get() or {'total_available': 0.0, 'total_earned': 0.0}
            
            new_available = max(0.0, current_data.get('total_available', 0.0) + amount)
            new_earned = current_data.get('total_earned', 0.0) + max(0, amount)
            
            profit_ref.update({
                'total_available': new_available,
                'total_earned': new_earned,
                'last_updated': datetime.now().isoformat()
            })
            
            print(f"💰 Profit wallet updated: {amount}")
            return True
        except Exception as e:
            print(f"❌ Error updating profit wallet: {e}")
            return False
    
    def _get_mock_user(self, user_id: str) -> Dict[str, Any]:
        """Get mock user for development"""
        return {
            'id': user_id,
            'name': 'Mock User',
            'email': 'mock@example.com',
            'phone': '08012345678',
            'wallet_balance': 1000.0,
            'is_verified': True,
            'created_at': datetime.now().isoformat()
        }
    
    def _get_mock_user_by_email(self, email: str) -> Dict[str, Any]:
        """Get mock user by email for development"""
        return {
            'id': 'mock_user_123',
            'name': 'Mock User',
            'email': email.lower(),
            'phone': '08012345678',
            'wallet_balance': 1000.0,
            'is_verified': True,
            'created_at': datetime.now().isoformat()
        }

# ==================== PAYSTACK SERVICE ====================
class PaystackService:
    def __init__(self):
        self.secret_key = os.getenv('PAYSTACK_SECRET_KEY')
        self.public_key = os.getenv('PAYSTACK_PUBLIC_KEY')
        self.base_url = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')
        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }
        
        print(f"🔧 Paystack Service Initialized: {self.base_url}")
        print(f"🔑 Public Key: {self.public_key[:10]}...")
    
    def initialize_transaction(self, email: str, amount: int, metadata: Dict = None, 
                             channel: str = None, callback_url: str = None) -> Dict[str, Any]:
        """Initialize a Paystack transaction"""
        url = f"{self.base_url}/transaction/initialize"
        
        payload = {
            'email': email,
            'amount': amount * 100,  # Convert to kobo
            'metadata': metadata or {},
            'currency': 'NGN'
        }
        
        if channel:
            payload['channels'] = [channel]
        
        if callback_url:
            payload['callback_url'] = callback_url
        
        print(f"🔄 Initializing Paystack transaction: {email} - ₦{amount}")
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            print(f"📊 Paystack Response: {result.get('status')}")
            
            if result.get('status'):
                print(f"✅ Transaction initialized: {result['data']['reference']}")
            else:
                print(f"❌ Paystack error: {result.get('message')}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Paystack API error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}
    
    def verify_transaction(self, reference: str) -> Dict[str, Any]:
        """Verify a Paystack transaction"""
        url = f"{self.base_url}/transaction/verify/{reference}"
        
        print(f"🔍 Verifying transaction: {reference}")
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            print(f"📊 Verification Response: {result.get('status')}")
            
            if result.get('status') and result['data']['status'] == 'success':
                print(f"✅ Transaction verified successfully: {reference}")
            else:
                print(f"❌ Transaction verification failed: {result.get('message')}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Paystack verification error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}
        except Exception as e:
            error_msg = f"Unexpected verification error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}
    
    def create_transfer_recipient(self, account_number: str, bank_code: str, 
                                account_name: str) -> Dict[str, Any]:
        """Create a transfer recipient"""
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
    
    def initiate_transfer(self, recipient: str, amount: int, reason: str = "Withdrawal") -> Dict[str, Any]:
        """Initiate a transfer"""
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
        """Verify Paystack webhook signature"""
        try:
            computed_signature = hmac.new(
                self.secret_key.encode('utf-8'),
                payload,
                hashlib.sha512
            ).hexdigest()
            
            return hmac.compare_digest(computed_signature, signature)
        except Exception as e:
            print(f"❌ Webhook signature verification failed: {e}")
            return False

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
    url = f"{self.base_url}/pay"  # This is correct
    
    payload = {
        'serviceID': service_id,
        'billersCode': billers_code,
        'variation_code': variation_code,
        'amount': amount,
        'phone': phone or '',
        'request_id': request_id or f"req_{int(datetime.now().timestamp())}"
    }
    
    try:
        response = requests.post(url, headers=self.headers, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'code': '099', 'response_description': str(e), 'content': str(e)}

    def verify_smartcard(self, service_id: str, billers_code: str) -> Dict[str, Any]:
        url = f"{self.base_url}/merchant-verify"  # This is correct
    
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

# ==================== TERMII SERVICE ====================
class TermiiService:
    def __init__(self):
        self.api_key = os.getenv('TERMII_API_KEY')
        self.base_url = "https://api.ng.termii.com/api"
    
    def send_sms(self, phone: str, message: str, sender_id: str = "Cheap4uApp") -> Dict[str, Any]:
        """Send SMS via Termii"""
        if not self.api_key:
            print("⚠️ Termii API key not configured")
            return {'status': 'success', 'message': 'Mock SMS sent'}
        
        url = f"{self.base_url}/sms/send"
        
        payload = {
            'to': phone,
            'from': sender_id,
            'sms': message,
            'type': 'plain',
            'channel': 'generic',
            'api_key': self.api_key
        }
        
        try:
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Termii SMS error: {e}")
            return {'status': 'error', 'message': str(e)}

# ==================== VALIDATION UTILITIES ====================
def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return False
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def validate_phone(phone: str) -> bool:
    """Validate Nigerian phone number"""
    if not phone:
        return False
    return len(phone) == 11 and phone.isdigit() and phone.startswith(('070', '080', '081', '090', '091'))

def validate_amount(amount: Any) -> Tuple[bool, float]:
    """Validate and parse amount"""
    try:
        if isinstance(amount, (int, float)):
            amount_float = float(amount)
        else:
            amount_float = float(str(amount).replace('₦', '').replace(',', '').strip())
        
        if amount_float <= 0:
            return False, 0
        return True, amount_float
    except (ValueError, TypeError):
        return False, 0

def validate_password(password: str) -> bool:
    """Validate password strength"""
    return len(password) >= 6

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ==================== FLASK APP ====================
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=['*'])  # Allow all origins for development

# Initialize services
print("🔄 Initializing services...")
firebase_client = FirebaseClient.get_instance()
paystack_service = PaystackService()
vtpass_service = VTPassService()
termii_service = TermiiService()

print("✅ All services initialized successfully!")
print("🚀 VTU Backend API Ready!")

# ==================== ROUTES ====================

@app.route('/')
def home():
    return jsonify({
        'message': '🚀 VTU Backend API is running!',
        'status': 'active',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'services': {
            'firebase': 'connected' if firebase_client.root_ref else 'disconnected',
            'paystack': 'configured' if paystack_service.secret_key else 'not configured',
            'vtpass': 'configured' if vtpass_service.api_key else 'not configured'
        }
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'VTU Backend API',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected' if firebase_client.root_ref else 'disconnected'
    })

# ==================== AUTH ROUTES ====================
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Register a new user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        print(f"📝 Registration attempt: {data.get('email')}")
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Validate phone
        if not validate_phone(data['phone']):
            return jsonify({'status': 'error', 'message': 'Invalid phone number format'}), 400
        
        # Validate password
        if not validate_password(data['password']):
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
        
        # Check if user already exists
        existing_user = firebase_client.get_user_by_email(data['email'])
        if existing_user:
            return jsonify({'status': 'error', 'message': 'User with this email already exists'}), 400
        
        # Create user data
        user_data = {
            'name': data['name'].strip(),
            'email': data['email'].lower().strip(),
            'phone': data['phone'].strip(),
            'password': hash_password(data['password']),
            'wallet_balance': 0.0,
            'referral_balance': 0.0,
            'is_verified': False,
            'is_premium': False,
            'joined_date': datetime.now().strftime("%Y-%m-%d"),
            'last_login': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        # Create user
        success, result = firebase_client.create_user(user_data)
        
        if success:
            # Get created user
            created_user = firebase_client.get_user(result)
            if created_user:
                # Remove password from response
                user_response = {k: v for k, v in created_user.items() if k != 'password'}
                
                return jsonify({
                    'status': 'success',
                    'message': 'User registered successfully',
                    'data': user_response
                }), 201
            else:
                return jsonify({
                    'status': 'success',
                    'message': 'User registered successfully',
                    'data': {'user_id': result, 'email': user_data['email']}
                }), 201
        else:
            return jsonify({'status': 'error', 'message': result}), 400
            
    except Exception as e:
        print(f"💥 Registration error: {str(e)}")
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
        
        # Find user
        user = firebase_client.get_user_by_email(data['email'])
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Verify password
        hashed_password = hash_password(data['password'])
        if user.get('password') != hashed_password:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Update last login
        firebase_client.update_user(user['id'], {
            'last_login': datetime.now().isoformat()
        })
        
        # Remove password from response
        user_response = {k: v for k, v in user.items() if k != 'password'}
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': user_response
        })
            
    except Exception as e:
        print(f"💥 Login error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}'}), 500

# ==================== PAYMENT ROUTES ====================
@app.route('/api/payment/initialize', methods=['POST'])
def initialize_payment():
    """Initialize Paystack payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        # Validate required fields
        if not data.get('email'):
            return jsonify({'status': 'error', 'message': 'Email is required'}), 400
        
        if not data.get('amount'):
            return jsonify({'status': 'error', 'message': 'Amount is required'}), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        
        if amount < 100:
            return jsonify({'status': 'error', 'message': 'Minimum amount is ₦100'}), 400
        
        if amount > 500000:
            return jsonify({'status': 'error', 'message': 'Maximum amount is ₦500,000'}), 400
        
        # Prepare metadata
        metadata = data.get('metadata', {})
        metadata.update({
            'user_email': data['email'],
            'service_type': data.get('service_type', 'wallet_funding'),
            'timestamp': datetime.now().isoformat()
        })
        
        # Initialize payment with Paystack
        result = paystack_service.initialize_transaction(
            email=data['email'],
            amount=int(amount),
            metadata=metadata,
            channel=data.get('channel'),
            callback_url=data.get('callback_url')
        )
        
        if result.get('status'):
            # Create transaction record
            tx_data = {
                'user_email': data['email'],
                'amount': float(amount),
                'payment_reference': result['data']['reference'],
                'authorization_url': result['data']['authorization_url'],
                'status': 'pending',
                'type': data.get('service_type', 'wallet_funding'),
                'metadata': metadata,
                'created_at': datetime.now().isoformat()
            }
            
            tx_id = firebase_client.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Payment initialized successfully',
                'data': {
                    **result['data'],
                    'transaction_id': tx_id
                }
            })
        else:
            error_msg = result.get('message', 'Payment initialization failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        print(f"💥 Payment initialization error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Payment initialization failed: {str(e)}'}), 500

@app.route('/api/payment/verify/<reference>', methods=['GET'])
def verify_payment(reference):
    """Verify payment status"""
    try:
        if not reference or reference == 'null':
            return jsonify({'status': 'error', 'message': 'Valid reference is required'}), 400
        
        print(f"🔍 Verifying payment: {reference}")
        
        # Check if we already have a successful transaction
        existing_tx = firebase_client.get_transaction_by_reference(reference)
        if existing_tx and existing_tx.get('status') == 'success':
            return jsonify({
                'status': 'success',
                'message': 'Payment already verified',
                'data': existing_tx,
                'from_cache': True
            })
        
        # Verify with Paystack
        result = paystack_service.verify_transaction(reference)
        
        if result.get('status') and result['data']['status'] == 'success':
            paystack_data = result['data']
            amount = paystack_data['amount'] / 100  # Convert from kobo to naira
            
            # Update transaction record
            tx_update = {
                'status': 'success',
                'verified_at': datetime.now().isoformat(),
                'paystack_response': paystack_data,
                'amount_verified': amount
            }
            
            # Update existing transaction or create new one
            if existing_tx:
                firebase_client.update_transaction(existing_tx['id'], tx_update)
                transaction_id = existing_tx['id']
            else:
                tx_data = {
                    'user_email': paystack_data.get('customer', {}).get('email', 'unknown'),
                    'amount': amount,
                    'payment_reference': reference,
                    'status': 'success',
                    'type': 'wallet_funding',
                    'paystack_response': paystack_data,
                    'verified_at': datetime.now().isoformat(),
                    'created_at': datetime.now().isoformat()
                }
                transaction_id = firebase_client.create_transaction(tx_data)
            
            # Credit user wallet for funding transactions
            user_email = paystack_data.get('customer', {}).get('email')
            if user_email:
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    success = firebase_client.update_user_wallet(user['id'], amount)
                    if success:
                        print(f"💰 Credited ₦{amount} to {user_email}")
                    else:
                        print(f"⚠️ Failed to credit wallet for {user_email}")
            
            response_data = {
                **paystack_data,
                'amount_in_naira': amount,
                'transaction_id': transaction_id
            }
            
            return jsonify({
                'status': 'success',
                'message': 'Payment verified successfully',
                'data': response_data
            })
        else:
            error_msg = result.get('message', 'Payment verification failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        print(f"💥 Verification error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Verification failed: {str(e)}'}), 500

@app.route('/api/payment/webhook/paystack', methods=['POST'])
def paystack_webhook():
    """Handle Paystack webhooks"""
    try:
        payload = request.get_data()
        signature = request.headers.get('x-paystack-signature')
        
        # Verify webhook signature
        if not paystack_service.verify_webhook_signature(payload, signature):
            print("❌ Invalid webhook signature")
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 400
        
        webhook_data = request.get_json()
        event = webhook_data.get('event')
        
        print(f"📨 Webhook received: {event}")
        
        if event == 'charge.success':
            data = webhook_data.get('data', {})
            reference = data.get('reference')
            amount = data.get('amount', 0) / 100
            user_email = data.get('customer', {}).get('email')
            
            print(f"💰 Charge success: {reference} - ₦{amount} - {user_email}")
            
            # Update transaction status
            existing_tx = firebase_client.get_transaction_by_reference(reference)
            if existing_tx:
                tx_update = {
                    'status': 'success',
                    'webhook_processed_at': datetime.now().isoformat(),
                    'paystack_webhook_data': webhook_data
                }
                firebase_client.update_transaction(existing_tx['id'], tx_update)
            else:
                # Create new transaction record
                tx_data = {
                    'user_email': user_email,
                    'amount': amount,
                    'payment_reference': reference,
                    'status': 'success',
                    'type': 'wallet_funding',
                    'paystack_webhook_data': webhook_data,
                    'webhook_processed_at': datetime.now().isoformat(),
                    'created_at': datetime.now().isoformat()
                }
                firebase_client.create_transaction(tx_data)
            
            # Credit user wallet
            if user_email:
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    success = firebase_client.update_user_wallet(user['id'], amount)
                    if success:
                        print(f"✅ Webhook: Credited ₦{amount} to {user_email}")
                    else:
                        print(f"❌ Webhook: Failed to credit {user_email}")
        
        return jsonify({'status': 'success', 'message': 'Webhook processed'})
        
    except Exception as e:
        print(f"💥 Webhook error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Webhook processing failed: {str(e)}'}), 500

# ==================== USER ROUTES ====================
@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get user profile"""
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'status': 'error', 'message': 'Email parameter is required'}), 400
        
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

# ==================== VTPASS ROUTES ====================
@app.route('/api/vtpass/pay', methods=['POST'])
def vtpass_pay():
    """Process VTPass payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['serviceID', 'billersCode', 'variation_code', 'amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        
        # Check user wallet balance if user_email provided
        user_email = data.get('user_email')
        if user_email:
            user = firebase_client.get_user_by_email(user_email)
            if user and user.get('wallet_balance', 0) < amount:
                return jsonify({'status': 'error', 'message': 'Insufficient wallet balance'}), 400
        
        # Make VTPass payment
        result = vtpass_service.pay(
            service_id=data['serviceID'],
            billers_code=data['billersCode'],
            variation_code=data['variation_code'],
            amount=amount,
            phone=data.get('phone')
        )
        
        # Record transaction
        tx_data = {
            'user_email': user_email,
            'type': 'vtpass_purchase',
            'service_id': data['serviceID'],
            'billers_code': data['billersCode'],
            'variation_code': data['variation_code'],
            'amount': amount,
            'status': 'success' if result.get('code') == '000' else 'failed',
            'vtpass_response': result,
            'created_at': datetime.now().isoformat()
        }
        
        tx_id = firebase_client.create_transaction(tx_data)
        
        if result.get('code') == '000':  # VTPass success code
            # Deduct from user wallet if applicable
            if user_email and user:
                firebase_client.update_user_wallet(user['id'], -amount)
            
            # Calculate and record profit (10% default)
            profit = amount * 0.1
            firebase_client.update_profit_wallet(profit)
            
            return jsonify({
                'status': 'success',
                'message': 'Payment processed successfully',
                'data': {
                    **result,
                    'transaction_id': tx_id,
                    'profit_amount': profit
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('response_description', 'VTPass payment failed'),
                'data': result
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'VTPass payment failed: {str(e)}'}), 500

@app.route('/api/vtpass/verify', methods=['POST'])
def vtpass_verify():
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
        return jsonify({'status': 'error', 'message': f'Verification failed: {str(e)}'}), 500

# ==================== OTP ROUTES ====================
@app.route('/api/otp/send', methods=['POST'])
def send_otp():
    """Send OTP to user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('phone'):
            return jsonify({'status': 'error', 'message': 'Phone number is required'}), 400
        
        if not validate_phone(data['phone']):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400
        
        # Generate OTP (for demo, use 123456)
        otp_code = "123456"  # In production, generate random code
        message = f"Your Cheap4u verification code is {otp_code}. It expires in 10 minutes."
        
        # Send SMS via Termii
        result = termii_service.send_sms(
            phone=data['phone'],
            message=message
        )
        
        if result.get('status') == 'success' or 'message' in result:
            # Store OTP in Firebase (in production)
            otp_data = {
                'phone': data['phone'],
                'code': otp_code,
                'expires_at': (datetime.now() + timedelta(minutes=10)).isoformat(),
                'created_at': datetime.now().isoformat()
            }
            firebase_client.create_transaction(otp_data)  # Using transactions collection for demo
            
            return jsonify({
                'status': 'success',
                'message': 'OTP sent successfully',
                'data': {
                    'otp_code': otp_code,  # Remove in production
                    'phone': data['phone']
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to send OTP')
            }), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send OTP: {str(e)}'}), 500

# ==================== UTILITY ROUTES ====================
@app.route('/api/utils/validate-phone', methods=['POST'])
def validate_phone_number():
    """Validate phone number and detect network"""
    try:
        data = request.get_json()
        if not data or not data.get('phone'):
            return jsonify({'status': 'error', 'message': 'Phone number is required'}), 400
        
        phone = data['phone']
        
        if not validate_phone(phone):
            return jsonify({'status': 'error', 'message': 'Invalid phone number format'}), 400
        
        # Detect network (simplified logic)
        network_prefixes = {
            'MTN': ['0803', '0806', '0703', '0706', '0813', '0816', '0810', '0814'],
            'Airtel': ['0802', '0808', '0708', '0812', '0701'],
            'Glo': ['0805', '0807', '0705', '0815', '0811'],
            '9mobile': ['0809', '0818', '0817', '0909']
        }
        
        prefix = phone[:4]
        network = None
        
        for net, prefixes in network_prefixes.items():
            if prefix in prefixes:
                network = net
                break
        
        return jsonify({
            'status': 'success',
            'data': {
                'phone': phone,
                'network': network,
                'is_valid': True
            }
        })
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Validation failed: {str(e)}'}), 500

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
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"🚀 Starting VTU Backend Server...")
    print(f"📍 Port: {port}")
    print(f"🐛 Debug: {debug}")
    print(f"🔑 Paystack: {'✅ Configured' if paystack_service.secret_key else '❌ Not Configured'}")
    print(f"🗄️  Firebase: {'✅ Connected' if firebase_client.root_ref else '❌ Disconnected'}")
    
    app.run(host='0.0.0.0', port=port, debug=debug) 
