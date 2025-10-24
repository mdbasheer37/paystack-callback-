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

# ==================== ENHANCED CONFIGURATION ====================

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

    # Paystack
    PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', 'sk_test_xxxxxxxxxxxxxx')
    PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', 'pk_test_xxxxxxxxxxxxxx')
    PAYSTACK_BASE_URL = 'https://api.paystack.co'
    
    # VTPass
    VTPASS_API_KEY = os.getenv('VTPASS_API_KEY', 'your_actual_vtpass_api_key')
    VTPASS_SECRET_KEY = os.getenv('VTPASS_SECRET_KEY', 'your_actual_vtpass_secret_key')
    VTPASS_BASE_URL = 'https://vtpass.com/api'
    
    # Termii
    TERMII_API_KEY = os.getenv('TERMII_API_KEY', 'test_termii_key')
    
    # Firebase
    FIREBASE_DB_URL = os.getenv('FIREBASE_DB_URL', 'https://vtu-app-default-rtdb.firebaseio.com/')
    
    # Admin emails
    ADMIN_EMAILS = ['admin@cheap4u.com', 'muhammadibrahim376@gmail.com']
    
    # COMPLETE VTPass Service IDs
    VTPASS_SERVICE_IDS = {
        'airtime': {
            'MTN': 'mtn',
            'Airtel': 'airtel',
            'Glo': 'glo',
            '9Mobile': 'etisalat'
        },
        'data': {
            'MTN': 'mtn-data',
            'Airtel': 'airtel-data',
            'Glo': 'glo-data',
            '9Mobile': 'etisalat-data'
        },
        'electricity': {
            'IKEDC': 'ikeja-electric',
            'EKEDC': 'eko-electric',
            'IBEDC': 'ibadan-electric',
            'AEDC': 'abuja-electric',
            'KEDCO': 'kano-electric',
            'PHED': 'portharcourt-electric',
            'JED': 'jos-electric'
        },
        'cable_tv': {
            'DSTV': 'dstv',
            'GOTV': 'gotv',
            'Startimes': 'startimes',
            'Showmax': 'showmax'
        },
        'exam_pins': {
            'WAEC': 'waec',
            'NECO': 'neco', 
            'JAMB': 'jamb',
            'NABTEB': 'nabteb'
        }
    }

# ==================== ENHANCED FIREBASE CLIENT ====================

class FirebaseClient:
    _instance = None

    def __init__(self):
        try:
            if not firebase_admin._apps:
                # For development, use mock credentials
                cred_dict = {
                    "type": "service_account",
                    "project_id": "vtu-app-dev",
                    "private_key_id": "mock-key-id",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nMOCK_KEY_FOR_DEVELOPMENT\n-----END PRIVATE KEY-----\n",
                    "client_email": "mock@vtu-app-dev.iam.gserviceaccount.com",
                    "client_id": "mock-client-id",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {
                    'databaseURL': Config.FIREBASE_DB_URL
                })
                print("✅ Firebase initialized successfully")
            self.root_ref = db.reference('/')
            self._setup_default_data()
        except Exception as e:
            print(f"❌ Firebase initialization failed: {str(e)}")
            # Fallback to mock mode
            self.root_ref = None
            self._setup_mock_data()

    def _setup_default_data(self):
        """Initialize default data structure"""
        try:
            # Initialize profit wallet if not exists
            if self.root_ref.child('profit_wallet').get() is None:
                self.root_ref.child('profit_wallet').set({
                    'total_available': 0.0,
                    'total_earned': 0.0,
                    'total_withdrawn': 0.0,
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

    def _setup_mock_data(self):
        """Setup mock data for development"""
        print("🔧 Running in mock mode - no Firebase connection")
        self.mock_users = {}
        self.mock_transactions = {}
        self.mock_profit_wallet = {
            'total_available': 0.0, 
            'total_earned': 0.0,
            'total_withdrawn': 0.0
        }
        self.mock_withdrawals = {}

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

            if self.root_ref:
                # Real Firebase
                user_ref = self.root_ref.child('users').push(user_data)
                user_id = user_ref.key
            else:
                # Mock mode
                user_id = f"user_{int(datetime.now().timestamp())}"
                self.mock_users[user_id] = user_data

            print(f"✅ User created: {user_id}")
            return True, user_id
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            return False, str(e)

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            if self.root_ref:
                user_ref = self.root_ref.child(f'users/{user_id}')
                user_data = user_ref.get()
                if user_data:
                    user_data['id'] = user_id
                    return user_data
            else:
                # Mock mode
                user_data = self.mock_users.get(user_id)
                if user_data:
                    user_data['id'] = user_id
                    return user_data
            return None
        except Exception as e:
            print(f"❌ Error getting user: {e}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            if self.root_ref:
                users_ref = self.root_ref.child('users')
                users = users_ref.get()
                if users:
                    for user_id, user_data in users.items():
                        if user_data.get('email') == email.lower():
                            user_data['id'] = user_id
                            return user_data
                    return None
            else:
                # Mock mode
                for user_id, user_data in self.mock_users.items():
                    if user_data.get('email') == email.lower():
                        user_data['id'] = user_id
                        return user_data
                return None
        except Exception as e:
            print(f"❌ Error getting user by email: {e}")
            return None

    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user data"""
        try:
            updates['updated_at'] = datetime.now().isoformat()
            if self.root_ref:
                self.root_ref.child(f'users/{user_id}').update(updates)
            else:
                # Mock mode
                if user_id in self.mock_users:
                    self.mock_users[user_id].update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating user: {e}")
            return False

    def update_user_wallet(self, user_id: str, amount: float) -> bool:
        """Update user wallet balance"""
        try:
            if self.root_ref:
                user_ref = self.root_ref.child(f'users/{user_id}')
                user_data = user_ref.get() or {}
            else:
                # Mock mode
                user_data = self.mock_users.get(user_id, {})

            current_balance = user_data.get('wallet_balance', 0.0)
            new_balance = max(0.0, float(current_balance) + amount)
            
            updates = {
                'wallet_balance': new_balance,
                'updated_at': datetime.now().isoformat()
            }

            if self.root_ref:
                user_ref.update(updates)
            else:
                # Mock mode
                if user_id in self.mock_users:
                    self.mock_users[user_id].update(updates)

            print(f"💰 Updated wallet for {user_id}: {current_balance} -> {new_balance}")
            return True
        except Exception as e:
            print(f"❌ Error updating wallet: {e}")
            return False

    def create_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """Create a transaction record"""
        try:
            transaction_data['created_at'] = datetime.now().isoformat()
            if self.root_ref:
                transaction_ref = self.root_ref.child('transactions').push(transaction_data)
                return transaction_ref.key
            else:
                # Mock mode
                tx_id = f"tx_{int(datetime.now().timestamp())}"
                self.mock_transactions[tx_id] = transaction_data
                return tx_id
        except Exception as e:
            print(f"❌ Error creating transaction: {e}")
            return f"mock_tx_{int(datetime.now().timestamp())}"

    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Get transaction by ID"""
        try:
            if self.root_ref:
                transaction_ref = self.root_ref.child(f'transactions/{transaction_id}')
                tx_data = transaction_ref.get()
                if tx_data:
                    tx_data['id'] = transaction_id
                    return tx_data
            else:
                # Mock mode
                tx_data = self.mock_transactions.get(transaction_id)
                if tx_data:
                    tx_data['id'] = transaction_id
                    return tx_data
            return None
        except Exception as e:
            print(f"❌ Error getting transaction: {e}")
            return None

    def get_transaction_by_reference(self, reference: str) -> Optional[Dict[str, Any]]:
        """Get transaction by payment reference"""
        try:
            if self.root_ref:
                transactions_ref = self.root_ref.child('transactions')
                transactions = transactions_ref.get()
                if transactions:
                    for tx_id, tx_data in transactions.items():
                        if tx_data.get('payment_reference') == reference:
                            tx_data['id'] = tx_id
                            return tx_data
                    return None
            else:
                # Mock mode
                for tx_id, tx_data in self.mock_transactions.items():
                    if tx_data.get('payment_reference') == reference:
                        tx_data['id'] = tx_id
                        return tx_data
                return None
        except Exception as e:
            print(f"❌ Error getting transaction by reference: {e}")
            return None

    def update_transaction(self, transaction_id: str, updates: Dict[str, Any]) -> bool:
        """Update transaction data"""
        try:
            if self.root_ref:
                self.root_ref.child(f'transactions/{transaction_id}').update(updates)
            else:
                # Mock mode
                if transaction_id in self.mock_transactions:
                    self.mock_transactions[transaction_id].update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating transaction: {e}")
            return False

    def update_profit_wallet(self, amount: float) -> bool:
        """Update profit wallet"""
        try:
            if self.root_ref:
                profit_ref = self.root_ref.child('profit_wallet')
                current_data = profit_ref.get() or {'total_available': 0.0, 'total_earned': 0.0}
            else:
                # Mock mode
                current_data = self.mock_profit_wallet

            new_available = max(0.0, current_data.get('total_available', 0.0) + amount)
            new_earned = current_data.get('total_earned', 0.0) + max(0, amount)
            
            updates = {
                'total_available': new_available,
                'total_earned': new_earned,
                'last_updated': datetime.now().isoformat()
            }

            if self.root_ref:
                profit_ref.update(updates)
            else:
                # Mock mode
                self.mock_profit_wallet.update(updates)

            print(f"💰 Profit wallet updated: {amount}")
            return True
        except Exception as e:
            print(f"❌ Error updating profit wallet: {e}")
            return False

    def create_profit_ledger_entry(self, ledger_data: Dict[str, Any]) -> str:
        """Create profit ledger entry"""
        try:
            if self.root_ref:
                ledger_ref = self.root_ref.child('profit_ledger').push(ledger_data)
                return ledger_ref.key
            else:
                # Mock mode
                ledger_id = f"ledger_{int(datetime.now().timestamp())}"
                return ledger_id
        except Exception as e:
            print(f"❌ Error creating profit ledger entry: {e}")
            return f"mock_ledger_{int(datetime.now().timestamp())}"

# ==================== PAYSTACK SERVICE ====================

class PaystackService:
    def __init__(self):
        self.secret_key = Config.PAYSTACK_SECRET_KEY
        self.public_key = Config.PAYSTACK_PUBLIC_KEY
        self.base_url = Config.PAYSTACK_BASE_URL
        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }

        print(f"🔧 Paystack Service Initialized: {self.base_url}")

    def initialize_transaction(self, email: str, amount: int, metadata: Dict = None, channel: str = None, callback_url: str = None) -> Dict[str, Any]:
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
            
            if result.get('status'):
                print(f"✅ Transaction initialized: {result['data']['reference']}")
                return result
            else:
                error_msg = result.get('message', 'Unknown Paystack error')
                print(f"❌ Paystack error: {error_msg}")
                return {'status': False, 'message': error_msg}
                
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
            
            if result.get('status') and result['data']['status'] == 'success':
                print(f"✅ Transaction verified successfully: {reference}")
                return result
            else:
                error_msg = result.get('message', 'Transaction verification failed')
                print(f"❌ Transaction verification failed: {error_msg}")
                return {'status': False, 'message': error_msg}
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Paystack verification error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}
        except Exception as e:
            error_msg = f"Unexpected verification error: {str(e)}"
            print(f"❌ {error_msg}")
            return {'status': False, 'message': error_msg}

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

# ==================== ENHANCED VTPASS SERVICE ====================

class VTPassService:
    def __init__(self):
        self.api_key = Config.VTPASS_API_KEY
        self.secret_key = Config.VTPASS_SECRET_KEY
        self.base_url = Config.VTPASS_BASE_URL
        self.headers = {
            'api-key': self.api_key,
            'secret-key': self.secret_key,
            'Content-Type': 'application/json'
        }
        print(f"🔧 VTPass Service Initialized: {self.base_url}")

    def make_request(self, endpoint, method="POST", data=None):
        """Generic VTPass request with enhanced error handling"""
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers, timeout=30)
            else:
                response = requests.post(url, headers=self.headers, json=data, timeout=30)
            
            response.raise_for_status()
            result = response.json()
            
            print(f"🔧 VTPass {method} {endpoint}: {result.get('code', 'No code')}")
            return result
            
        except requests.exceptions.Timeout:
            return {'code': '099', 'response_description': 'VTPass API timeout'}
        except requests.exceptions.ConnectionError:
            return {'code': '099', 'response_description': 'VTPass API connection error'}
        except requests.exceptions.HTTPError as e:
            return {'code': '099', 'response_description': f'VTPass HTTP error: {str(e)}'}
        except Exception as e:
            return {'code': '099', 'response_description': f'VTPass error: {str(e)}'}

    def pay(self, service_id, billers_code, variation_code, amount, phone=None):
        """Process VTPass payment with validation"""
        # Validate inputs
        if not all([service_id, billers_code, variation_code, amount]):
            return {'code': '099', 'response_description': 'Missing required parameters'}
        
        if amount <= 0:
            return {'code': '099', 'response_description': 'Invalid amount'}
        
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code,
            'variation_code': variation_code,
            'amount': amount,
            'phone': phone or '',
            'request_id': f"req_{int(datetime.now().timestamp())}"
        }
        
        print(f"🔧 VTPass Pay Request: {payload}")
        return self.make_request("pay", "POST", payload)

    def verify_service(self, service_id, billers_code):
        """Verify service (meter, smartcard, etc.)"""
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code
        }
        return self.make_request("merchant-verify", "POST", payload)

    def get_balance(self):
        """Get VTPass wallet balance"""
        return self.make_request("balance", "GET")

    def get_service_variations(self, service_id):
        """Get available variations for a service"""
        return self.make_request(f"service-variations?serviceID={service_id}", "GET")

    def get_services(self):
        """Get all available services"""
        return self.make_request("services", "GET")

# ==================== TERMII SERVICE ====================

class TermiiService:
    def __init__(self):
        self.api_key = Config.TERMII_API_KEY
        self.base_url = "https://api.ng.termii.com/api"

    def send_sms(self, phone: str, message: str, sender_id: str = "Cheap4uApp") -> Dict[str, Any]:
        """Send SMS via Termii"""
        if not self.api_key:
            print("⚠️ Termii API key not configured - using mock SMS")
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
    pattern = r'^[\w.-]+@[\w.-]+\.\w+$'
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

def is_admin(user_email):
    """Check if user is admin"""
    return user_email in Config.ADMIN_EMAILS

def calculate_profit(service_type, amount, service_details=None):
    """Calculate profit based on service type"""
    service_details = service_details or {}
    
    profit_rates = {
        'airtime': 0.02,      # 2% for airtime
        'data': 0.05,         # 5% for data
        'electricity': 0.02,  # 2% for electricity
        'cable_tv': 0.05,     # 5% for cable TV
        'exam_pins': 0.10     # 10% for exam pins
    }
    
    rate = profit_rates.get(service_type, 0.03)  # 3% default
    return amount * rate

def validate_meter_number(meter_number, disco):
    """Validate electricity meter number"""
    if not meter_number or len(meter_number) < 6:
        return False
    return meter_number.isdigit()

def validate_smartcard_number(smartcard_number):
    """Validate cable TV smartcard number"""
    if not smartcard_number or len(smartcard_number) < 6:
        return False
    return smartcard_number.isdigit()

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

# ==================== UTILITY FUNCTIONS ====================

def handle_vtpass_response(result, request_data, service_type, amount):
    """Handle VTPass response and create transaction record"""
    try:
        user_email = request_data.get('user_email')
        user = None
        
        # Check user and wallet if user_email provided
        if user_email:
            user = firebase_client.get_user_by_email(user_email)
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
            # Deduct from wallet first for successful transactions
            if result.get('code') == '000':
                success = firebase_client.update_user_wallet(user['id'], -amount)
                if not success:
                    return jsonify({'status': 'error', 'message': 'Failed to deduct from wallet'}), 400

        # Calculate profit
        profit_amount = calculate_profit(service_type, amount, request_data)

        # Create transaction record
        tx_data = {
            'user_email': user_email,
            'type': service_type,
            'service_type': service_type,
            'service_id': request_data.get('service_id'),
            'billers_code': request_data.get('billers_code'),
            'variation_code': request_data.get('variation_code'),
            'amount': amount,
            'profit': profit_amount,
            'status': 'success' if result.get('code') == '000' else 'failed',
            'vtpass_response': result,
            'request_data': request_data,
            'created_at': datetime.now().isoformat()
        }
        
        tx_id = firebase_client.create_transaction(tx_data)

        # Handle response
        if result.get('code') == '000':
            # Add profit to profit wallet
            firebase_client.update_profit_wallet(profit_amount)
            
            # Record profit ledger entry
            ledger_data = {
                'transaction_id': tx_id,
                'amount': profit_amount,
                'type': f'{service_type}_profit',
                'service_type': service_type,
                'status': 'available',
                'created_at': datetime.now().isoformat()
            }
            firebase_client.create_profit_ledger_entry(ledger_data)

            response_data = {
                **result,
                'transaction_id': tx_id,
                'profit_amount': profit_amount
            }

            # Add service-specific data
            if service_type == 'electricity' and result.get('content', {}).get('Token'):
                response_data['token'] = result['content']['Token']
                response_data['units'] = result['content'].get('Units')

            return jsonify({
                'status': 'success',
                'message': f'{service_type.replace("_", " ").title()} purchase successful',
                'data': response_data
            })
        else:
            # Refund wallet if payment failed
            if user_email and user:
                firebase_client.update_user_wallet(user['id'], amount)
            
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({
                'status': 'error',
                'message': f'VTPass Error: {error_msg}',
                'data': result
            }), 400

    except Exception as e:
        print(f"💥 Response handling error: {str(e)}")
        # Refund on any exception
        if user_email and user:
            firebase_client.update_user_wallet(user['id'], amount)
        return jsonify({'status': 'error', 'message': f'Transaction processing failed: {str(e)}'}), 500

# ==================== ROUTES ====================

@app.route('/')
def home():
    return jsonify({
        'message': '🚀 VTU Backend API is running!',
        'status': 'active',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'services': {
            'firebase': 'connected' if firebase_client.root_ref else 'mock_mode',
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
        'database': 'connected' if firebase_client.root_ref else 'mock_mode'
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

        print(f"💰 Payment initialization request: {data}")
        
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
            'timestamp': datetime.now().isoformat(),
            'custom_reference': f"VTU_{int(datetime.now().timestamp())}"
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
                'paystack_response': result,
                'created_at': datetime.now().isoformat()
            }
            
            tx_id = firebase_client.create_transaction(tx_data)
            
            response_data = {
                **result['data'],
                'transaction_id': tx_id,
                'amount_in_naira': amount
            }
            
            return jsonify({
                'status': 'success',
                'message': 'Payment initialized successfully',
                'data': response_data
            })
        else:
            error_msg = result.get('message', 'Payment initialization failed')
            print(f"❌ Paystack initialization failed: {error_msg}")
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
            print(f"✅ Using cached successful transaction: {reference}")
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
            user_email = paystack_data.get('customer', {}).get('email', 'unknown')
            
            print(f"✅ Payment verified successfully: {reference} - ₦{amount} - {user_email}")

            # Update or create transaction record
            tx_update = {
                'status': 'success',
                'verified_at': datetime.now().isoformat(),
                'paystack_response': paystack_data,
                'amount_verified': amount,
                'user_email': user_email
            }
            
            if existing_tx:
                firebase_client.update_transaction(existing_tx['id'], tx_update)
                transaction_id = existing_tx['id']
            else:
                tx_data = {
                    'user_email': user_email,
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
            if user_email and user_email != 'unknown':
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    success = firebase_client.update_user_wallet(user['id'], amount)
                    if success:
                        print(f"💰 Credited ₦{amount} to {user_email}")
                    else:
                        print(f"⚠️ Failed to credit wallet for {user_email}")
                else:
                    print(f"⚠️ User not found for email: {user_email}")

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
            print(f"❌ Payment verification failed: {error_msg}")
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

        print(f"📨 Webhook received: {signature}")

        # Verify webhook signature
        if not paystack_service.verify_webhook_signature(payload, signature):
            print("❌ Invalid webhook signature")
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 400

        webhook_data = request.get_json()
        event = webhook_data.get('event')
        print(f"📨 Webhook event: {event}")

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
                else:
                    print(f"⚠️ Webhook: User not found for {user_email}")

            return jsonify({'status': 'success', 'message': 'Webhook processed'})

    except Exception as e:
        print(f"💥 Webhook error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Webhook processing failed: {str(e)}'}), 500

# ==================== VTPASS ROUTES ====================

@app.route('/api/vtpass/services', methods=['GET'])
def get_vtpass_services():
    """Get all available VTPass services"""
    try:
        result = vtpass_service.get_services()
        if result.get('code') == '000':
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to get services'
            }), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/vtpass/variations/<service_id>', methods=['GET'])
def get_service_variations(service_id):
    """Get available variations for a service"""
    try:
        result = vtpass_service.get_service_variations(service_id)
        if result.get('code') == '000':
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to get service variations'
            }), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/vtpass/airtime', methods=['POST'])
def purchase_airtime():
    """Purchase airtime through VTPass"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        print(f"📞 Airtime purchase request: {data}")
        
        # Validate required fields
        required_fields = ['network', 'phone', 'amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Validate network
        network = data['network']
        if network not in Config.VTPASS_SERVICE_IDS['airtime']:
            return jsonify({'status': 'error', 'message': 'Unsupported network'}), 400

        # Validate phone
        if not validate_phone(data['phone']):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400

        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid or amount < 50 or amount > 50000:
            return jsonify({'status': 'error', 'message': 'Amount must be between ₦50 and ₦50,000'}), 400

        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['airtime'][network]
        
        # For airtime, billersCode is the phone number
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['phone'],  # For airtime, phone is billersCode
            variation_code=service_id,   # For airtime, service_id is variation_code
            amount=amount,
            phone=data['phone']
        )

        return handle_vtpass_response(result, data, 'airtime', amount)

    except Exception as e:
        print(f"💥 Airtime purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Airtime purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/data', methods=['POST'])
def purchase_data():
    """Purchase data bundle through VTPass"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        print(f"📱 Data purchase request: {data}")
        
        # Validate required fields
        required_fields = ['network', 'phone', 'plan_code', 'amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Validate network
        network = data['network']
        if network not in Config.VTPASS_SERVICE_IDS['data']:
            return jsonify({'status': 'error', 'message': 'Unsupported network'}), 400

        # Validate phone
        if not validate_phone(data['phone']):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400

        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400

        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['data'][network]
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['phone'],
            variation_code=data['plan_code'],
            amount=amount,
            phone=data['phone']
        )

        return handle_vtpass_response(result, data, 'data', amount)

    except Exception as e:
        print(f"💥 Data purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Data purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/electricity', methods=['POST'])
def purchase_electricity():
    """Purchase electricity token through VTPass"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        print(f"⚡ Electricity purchase request: {data}")
        
        # Validate required fields
        required_fields = ['disco', 'meter_number', 'meter_type', 'amount', 'phone']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Validate disco
        disco = data['disco']
        if disco not in Config.VTPASS_SERVICE_IDS['electricity']:
            return jsonify({'status': 'error', 'message': 'Unsupported electricity provider'}), 400

        # Validate meter number
        if not validate_meter_number(data['meter_number'], disco):
            return jsonify({'status': 'error', 'message': 'Invalid meter number'}), 400

        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid or amount < 100 or amount > 100000:
            return jsonify({'status': 'error', 'message': 'Amount must be between ₦100 and ₦100,000'}), 400

        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['electricity'][disco]
        
        # Map meter type to variation code
        meter_type = data['meter_type'].lower()
        variation_code = f"{service_id}-{meter_type}"

        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['meter_number'],
            variation_code=variation_code,
            amount=amount,
            phone=data['phone']
        )

        return handle_vtpass_response(result, data, 'electricity', amount)

    except Exception as e:
        print(f"💥 Electricity purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Electricity purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/cable-tv', methods=['POST'])
def purchase_cable_tv():
    """Purchase cable TV subscription through VTPass"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        print(f"📺 Cable TV purchase request: {data}")
        
        # Validate required fields
        required_fields = ['provider', 'smartcard_number', 'package_code', 'amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Validate provider
        provider = data['provider']
        if provider not in Config.VTPASS_SERVICE_IDS['cable_tv']:
            return jsonify({'status': 'error', 'message': 'Unsupported cable provider'}), 400

        # Validate smartcard number
        if not validate_smartcard_number(data['smartcard_number']):
            return jsonify({'status': 'error', 'message': 'Invalid smartcard number'}), 400

        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400

        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['cable_tv'][provider]
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['smartcard_number'],
            variation_code=data['package_code'],
            amount=amount,
            phone=data.get('phone', '')
        )

        return handle_vtpass_response(result, data, 'cable_tv', amount)

    except Exception as e:
        print(f"💥 Cable TV purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Cable TV purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/exam-pins', methods=['POST'])
def purchase_exam_pins():
    """Purchase exam pins through VTPass"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        print(f"🎓 Exam PIN purchase request: {data}")
        
        # Validate required fields
        required_fields = ['exam_type', 'quantity', 'amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error', 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Validate exam type
        exam_type = data['exam_type']
        if exam_type not in Config.VTPASS_SERVICE_IDS['exam_pins']:
            return jsonify({'status': 'error', 'message': 'Unsupported exam type'}), 400

        # Validate quantity
        try:
            quantity = int(data['quantity'])
            if quantity < 1 or quantity > 10:
                return jsonify({'status': 'error', 'message': 'Quantity must be between 1 and 10'}), 400
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Invalid quantity'}), 400

        # Validate amount
        valid, amount = validate_amount(data['amount'])
        if not valid or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400

        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['exam_pins'][exam_type]
        
        # For exam pins, we need to generate a unique billersCode
        billers_code = f"exam_{int(datetime.now().timestamp())}"
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=billers_code,
            variation_code=service_id,
            amount=amount,
            phone=data.get('phone', '')
        )

        return handle_vtpass_response(result, data, 'exam_pins', amount)

    except Exception as e:
        print(f"💥 Exam PIN purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Exam PIN purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/verify', methods=['POST'])
def vtpass_verify():
    """Enhanced service verification"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400

        if not data.get('serviceID') or not data.get('billersCode'):
            return jsonify({'status': 'error', 'message': 'serviceID and billersCode are required'}), 400

        result = vtpass_service.verify_service(
            service_id=data['serviceID'],
            billers_code=data['billersCode']
        )

        if result.get('code') == '000':
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            error_msg = result.get('response_description', 'Verification failed')
            return jsonify({
                'status': 'error',
                'message': error_msg,
                'data': result
            }), 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Verification failed: {str(e)}'}), 500

@app.route('/api/vtpass/balance', methods=['GET'])
def vtpass_balance():
    """Get VTPass wallet balance"""
    try:
        result = vtpass_service.get_balance()
        if result.get('code') == '000':
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to get balance'
            }), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Balance check failed: {str(e)}'}), 500

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/profit', methods=['GET'])
def get_profit_summary():
    """Admin-only profit summary"""
    try:
        # Get user email from query parameter
        user_email = request.args.get('user_email')
        
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        # Check if user is admin
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        # Get all transactions
        if firebase_client.root_ref:
            transactions_ref = firebase_client.root_ref.child('transactions')
            transactions = transactions_ref.get() or {}
        else:
            transactions = firebase_client.mock_transactions
        
        # Get profit wallet
        if firebase_client.root_ref:
            profit_ref = firebase_client.root_ref.child('profit_wallet')
            profit_data = profit_ref.get() or {'total_available': 0.0, 'total_earned': 0.0, 'total_withdrawn': 0.0}
        else:
            profit_data = firebase_client.mock_profit_wallet
        
        # Calculate profits by category
        profit_summary = {
            'total_available': profit_data.get('total_available', 0.0),
            'total_earned': profit_data.get('total_earned', 0.0),
            'total_withdrawn': profit_data.get('total_withdrawn', 0.0),
            'by_category': {
                'data': {'count': 0, 'amount': 0.0},
                'airtime': {'count': 0, 'amount': 0.0},
                'electricity': {'count': 0, 'amount': 0.0},
                'cable_tv': {'count': 0, 'amount': 0.0},
                'exam_pins': {'count': 0, 'amount': 0.0},
                'wallet_funding': {'count': 0, 'amount': 0.0}
            },
            'recent_transactions': []
        }
        
        for tx_id, tx_data in transactions.items():
            if tx_data.get('status') == 'success' and tx_data.get('profit', 0) > 0:
                profit = tx_data.get('profit', 0.0)
                tx_type = tx_data.get('type', 'unknown').lower()
                
                # Categorize
                if 'data' in tx_type:
                    profit_summary['by_category']['data']['count'] += 1
                    profit_summary['by_category']['data']['amount'] += profit
                elif 'airtime' in tx_type:
                    profit_summary['by_category']['airtime']['count'] += 1
                    profit_summary['by_category']['airtime']['amount'] += profit
                elif 'electric' in tx_type:
                    profit_summary['by_category']['electricity']['count'] += 1
                    profit_summary['by_category']['electricity']['amount'] += profit
                elif 'cable' in tx_type or 'tv' in tx_type:
                    profit_summary['by_category']['cable_tv']['count'] += 1
                    profit_summary['by_category']['cable_tv']['amount'] += profit
                elif 'exam' in tx_type or 'pin' in tx_type:
                    profit_summary['by_category']['exam_pins']['count'] += 1
                    profit_summary['by_category']['exam_pins']['amount'] += profit
                elif 'funding' in tx_type:
                    profit_summary['by_category']['wallet_funding']['count'] += 1
                    profit_summary['by_category']['wallet_funding']['amount'] += profit
                
                # Add to recent transactions
                if len(profit_summary['recent_transactions']) < 10:
                    profit_summary['recent_transactions'].append({
                        'id': tx_id,
                        'type': tx_data.get('type', ''),
                        'amount': tx_data.get('amount', 0),
                        'profit': profit,
                        'date': tx_data.get('created_at', ''),
                        'service': tx_data.get('service_id', '')
                    })
        
        return jsonify({
            'status': 'success',
            'data': profit_summary
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/profit/withdraw', methods=['POST'])
def withdraw_profit():
    """Withdraw profit to bank account"""
    try:
        data = request.get_json()
        user_email = data.get('user_email')
        amount = data.get('amount')
        bank_details = data.get('bank_details')
        
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        # Check if user is admin
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        if not amount or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Valid amount required'}), 400
        
        if not bank_details:
            return jsonify({'status': 'error', 'message': 'Bank details required'}), 400
        
        # Get current profit wallet balance
        if firebase_client.root_ref:
            profit_ref = firebase_client.root_ref.child('profit_wallet')
            profit_data = profit_ref.get() or {'total_available': 0.0}
        else:
            profit_data = firebase_client.mock_profit_wallet
        
        available_balance = profit_data.get('total_available', 0.0)
        
        if amount > available_balance:
            return jsonify({
                'status': 'error', 
                'message': f'Insufficient profit balance. Available: ₦{available_balance:,.2f}'
            }), 400
        
        # Process withdrawal
        withdrawal_id = f"wd_{int(datetime.now().timestamp())}"
        withdrawal_data = {
            'id': withdrawal_id,
            'user_email': user_email,
            'amount': amount,
            'bank_details': bank_details,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'processed_at': None
        }
        
        # Record withdrawal
        if firebase_client.root_ref:
            firebase_client.root_ref.child(f'withdrawals/{withdrawal_id}').set(withdrawal_data)
        else:
            firebase_client.mock_withdrawals[withdrawal_id] = withdrawal_data
        
        # Update profit wallet (reserve the amount)
        new_balance = available_balance - amount
        if firebase_client.root_ref:
            profit_ref.update({
                'total_available': new_balance,
                'total_withdrawn': profit_data.get('total_withdrawn', 0.0) + amount,
                'last_updated': datetime.now().isoformat()
            })
        else:
            firebase_client.mock_profit_wallet.update({
                'total_available': new_balance,
                'total_withdrawn': firebase_client.mock_profit_wallet.get('total_withdrawn', 0.0) + amount
            })
        
        print(f"💸 Withdrawal requested: ₦{amount:,.2f} by {user_email}")
        
        return jsonify({
            'status': 'success',
            'message': 'Withdrawal request submitted successfully',
            'data': {
                'withdrawal_id': withdrawal_id,
                'amount': amount,
                'new_balance': new_balance,
                'status': 'pending'
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/withdrawals', methods=['GET'])
def get_withdrawal_history():
    """Get withdrawal history"""
    try:
        user_email = request.args.get('user_email')
        
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        # Get withdrawals
        if firebase_client.root_ref:
            withdrawals_ref = firebase_client.root_ref.child('withdrawals')
            withdrawals = withdrawals_ref.get() or {}
        else:
            withdrawals = getattr(firebase_client, 'mock_withdrawals', {})
        
        # Filter by user email and sort by date
        user_withdrawals = []
        for wd_id, wd_data in withdrawals.items():
            if wd_data.get('user_email') == user_email:
                user_withdrawals.append({
                    'id': wd_id,
                    **wd_data
                })
        
        # Sort by date (newest first)
        user_withdrawals.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify({
            'status': 'success',
            'data': user_withdrawals
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
    print(f"🔧 VTPass: {'✅ Configured' if vtpass_service.api_key else '❌ Not Configured'}")
    print(f"🗄️ Firebase: {'✅ Connected' if firebase_client.root_ref else '🔧 Mock Mode'}")
    print(f"👑 Admin Emails: {Config.ADMIN_EMAILS}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
