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
from typing import Dict, Any, Optional, Tuple, List
import re
import uuid
import random
from dotenv import load_dotenv
import traceback

# Load environment variables
load_dotenv()

print("🚀 Starting VTU Backend Initialization...")

# ==================== ENHANCED CONFIGURATION ====================

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Paystack
    PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
    PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', '')
    PAYSTACK_BASE_URL = 'https://api.paystack.co'
    
    # VTPass
    VTPASS_API_KEY = os.getenv('VTPASS_API_KEY', '')
    VTPASS_SECRET_KEY = os.getenv('VTPASS_SECRET_KEY', '')
    VTPASS_BASE_URL = 'https://vtpass.com/api'
    
    # Termii
    TERMII_API_KEY = os.getenv('TERMII_API_KEY', '')
    
    # Firebase
    FIREBASE_DB_URL = os.getenv('FIREBASE_DB_URL', '')
    FIREBASE_CREDENTIALS = os.getenv('FIREBASE_CREDENTIALS', '')
    
    # Admin emails
    ADMIN_EMAILS = ['admin@cheap4u.com', 'muhammadibrahim376@gmail.com']
    
    # VTPass Service IDs
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
    
    # Variation Codes
    VTPASS_VARIATION_CODES = {
        'electricity': {
            'prepaid': 'prepaid',
            'postpaid': 'postpaid'
        },
        'exam_pins': {
            'WAEC': 'waec',
            'NECO': 'neco',
            'JAMB': 'jamb',
            'NABTEB': 'nabteb'
        }
    }

# ==================== PRICING CONFIGURATION ====================

class PricingConfig:
    """Pricing configuration with markups"""
    
    PERCENTAGE_MARKUPS = {
        'airtime': 0.05,       # 5% markup
        'data': 0.10,          # 10% markup
        'electricity': 0.05,   # 5% markup
        'cable_tv': 0.08,      # 8% markup
        'exam_pins': 0.15,     # 15% markup
        'wallet_funding': 0.015, # 1.5% from payment processing
    }
    
    MINIMUM_PROFITS = {
        'airtime': 5,       # ₦5 minimum
        'data': 10,         # ₦10 minimum
        'electricity': 10,  # ₦10 minimum
        'cable_tv': 20,     # ₦20 minimum
        'exam_pins': 50,    # ₦50 minimum
    }
    
    @staticmethod
    def calculate_selling_price(base_price, service_type):
        """Calculate final price to charge customers"""
        if service_type not in PricingConfig.PERCENTAGE_MARKUPS:
            return base_price
        
        markup_rate = PricingConfig.PERCENTAGE_MARKUPS[service_type]
        selling_price = base_price * (1 + markup_rate)
        selling_price = round(selling_price / 10) * 10
        
        return selling_price
    
    @staticmethod
    def calculate_profit_amount(selling_price, base_price, service_type):
        """Calculate actual profit amount with minimum profit guarantee"""
        profit = selling_price - base_price
        
        min_profit = PricingConfig.MINIMUM_PROFITS.get(service_type, 0)
        if profit < min_profit:
            profit = min_profit
            selling_price = base_price + profit
        
        return profit, selling_price

# ==================== FIREBASE CLIENT ====================

class FirebaseClient:
    _instance = None
    
    def __init__(self):
        try:
            if not firebase_admin._apps:
                # Initialize Firebase
                if Config.FIREBASE_CREDENTIALS:
                    cred_dict = json.loads(Config.FIREBASE_CREDENTIALS)
                    cred = credentials.Certificate(cred_dict)
                else:
                    # For development only
                    cred_dict = {
                        "type": "service_account",
                        "project_id": "vtu-app-dev",
                        "private_key_id": "mock-key-id",
                        "private_key": "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n",
                        "client_email": "mock@vtu-app-dev.iam.gserviceaccount.com",
                        "client_id": "mock-client-id"
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
                    'transaction_count': 0,
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
            'total_withdrawn': 0.0,
            'transaction_count': 0
        }
        self.mock_withdrawals = {}
        self.mock_referral_transactions = {}
        self.mock_profit_ledger = {}
        self.mock_otp_records = {}
        self.mock_sessions = {}
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    # ==================== USER METHODS ====================
    
    def create_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """Create a new user"""
        try:
            user_data['created_at'] = datetime.now().isoformat()
            user_data['updated_at'] = datetime.now().isoformat()
            user_data['last_login'] = datetime.now().isoformat()
            
            if self.root_ref:
                self.root_ref.child(f'users/{user_id}').set(user_data)
            else:
                self.mock_users[user_id] = user_data
            
            print(f"✅ User created: {user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            if self.root_ref:
                user_data = self.root_ref.child(f'users/{user_id}').get()
            else:
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
                for user_id, user_data in self.mock_users.items():
                    if user_data.get('email') == email.lower():
                        user_data['id'] = user_id
                        return user_data
                return None
                
        except Exception as e:
            print(f"❌ Error getting user by email: {e}")
            return None
    
    def get_user_by_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        """Get user by phone number"""
        try:
            if self.root_ref:
                users_ref = self.root_ref.child('users')
                users = users_ref.get()
                if users:
                    for user_id, user_data in users.items():
                        if user_data.get('phone') == phone:
                            user_data['id'] = user_id
                            return user_data
                    return None
            else:
                for user_id, user_data in self.mock_users.items():
                    if user_data.get('phone') == phone:
                        user_data['id'] = user_id
                        return user_data
                return None
                
        except Exception as e:
            print(f"❌ Error getting user by phone: {e}")
            return None
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user data"""
        try:
            updates['updated_at'] = datetime.now().isoformat()
            if self.root_ref:
                self.root_ref.child(f'users/{user_id}').update(updates)
            else:
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
                if user_id in self.mock_users:
                    self.mock_users[user_id].update(updates)
            
            print(f"💰 Updated wallet for {user_id}: {current_balance} -> {new_balance}")
            return True
            
        except Exception as e:
            print(f"❌ Error updating wallet: {e}")
            return False
    
    # ==================== TRANSACTION METHODS ====================
    
    def create_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """Create a transaction record"""
        try:
            transaction_data['created_at'] = datetime.now().isoformat()
            if self.root_ref:
                transaction_ref = self.root_ref.child('transactions').push(transaction_data)
                return transaction_ref.key
            else:
                tx_id = f"tx_{int(datetime.now().timestamp())}"
                self.mock_transactions[tx_id] = transaction_data
                return tx_id
                
        except Exception as e:
            print(f"❌ Error creating transaction: {e}")
            return f"mock_tx_{int(datetime.now().timestamp())}"
    
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
                if transaction_id in self.mock_transactions:
                    self.mock_transactions[transaction_id].update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating transaction: {e}")
            return False
    
    # ==================== PROFIT METHODS ====================
    
    def update_profit_wallet(self, amount: float, transaction_type: str = "profit") -> bool:
        """Update profit wallet"""
        try:
            if self.root_ref:
                profit_ref = self.root_ref.child('profit_wallet')
                current_data = profit_ref.get() or {
                    'total_available': 0.0,
                    'total_earned': 0.0,
                    'total_withdrawn': 0.0,
                    'transaction_count': 0,
                    'last_updated': datetime.now().isoformat()
                }
            else:
                current_data = self.mock_profit_wallet
            
            if transaction_type == "profit":
                new_available = current_data.get('total_available', 0.0) + amount
                new_earned = current_data.get('total_earned', 0.0) + amount
                transaction_count = current_data.get('transaction_count', 0) + 1
                new_withdrawn = current_data.get('total_withdrawn', 0.0)
            elif transaction_type == "withdrawal":
                new_available = current_data.get('total_available', 0.0) - amount
                new_earned = current_data.get('total_earned', 0.0)
                new_withdrawn = current_data.get('total_withdrawn', 0.0) + amount
                transaction_count = current_data.get('transaction_count', 0)
            else:
                return False
            
            new_available = max(0.0, new_available)
            
            updates = {
                'total_available': new_available,
                'total_earned': new_earned,
                'total_withdrawn': new_withdrawn,
                'transaction_count': transaction_count,
                'last_updated': datetime.now().isoformat()
            }
            
            if self.root_ref:
                profit_ref.update(updates)
            else:
                self.mock_profit_wallet.update(updates)
            
            print(f"💰 Profit Wallet: {transaction_type} ₦{amount}. Available: ₦{new_available}")
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
                ledger_id = f"ledger_{int(datetime.now().timestamp())}"
                self.mock_profit_ledger[ledger_id] = ledger_data
                return ledger_id
        except Exception as e:
            print(f"❌ Error creating profit ledger entry: {e}")
            return f"mock_ledger_{int(datetime.now().timestamp())}"
    
    # ==================== OTP METHODS ====================
    
    def create_otp_record(self, user_id: str, otp_data: Dict[str, Any]) -> bool:
        """Create OTP record"""
        try:
            if self.root_ref:
                self.root_ref.child(f'otp_records/{user_id}').set(otp_data)
            else:
                self.mock_otp_records[user_id] = otp_data
            return True
        except Exception as e:
            print(f"❌ Error creating OTP record: {e}")
            return False
    
    def get_otp_record(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get OTP record by user ID"""
        try:
            if self.root_ref:
                otp_data = self.root_ref.child(f'otp_records/{user_id}').get()
            else:
                otp_data = self.mock_otp_records.get(user_id)
            return otp_data
        except Exception as e:
            print(f"❌ Error getting OTP record: {e}")
            return None
    
    def update_otp_record(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update OTP record"""
        try:
            if self.root_ref:
                self.root_ref.child(f'otp_records/{user_id}').update(updates)
            else:
                if user_id in self.mock_otp_records:
                    self.mock_otp_records[user_id].update(updates)
            return True
        except Exception as e:
            print(f"❌ Error updating OTP record: {e}")
            return False
    
    # ==================== SESSION METHODS ====================
    
    def create_session(self, token: str, session_data: Dict[str, Any]) -> bool:
        """Create session record"""
        try:
            if self.root_ref:
                self.root_ref.child(f'sessions/{token}').set(session_data)
            else:
                self.mock_sessions[token] = session_data
            return True
        except Exception as e:
            print(f"❌ Error creating session: {e}")
            return False
    
    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        try:
            if self.root_ref:
                return self.root_ref.child(f'sessions/{token}').get()
            else:
                return self.mock_sessions.get(token)
        except Exception as e:
            print(f"❌ Error getting session: {e}")
            return None
    
    def delete_session(self, token: str) -> bool:
        """Delete session"""
        try:
            if self.root_ref:
                self.root_ref.child(f'sessions/{token}').delete()
            else:
                if token in self.mock_sessions:
                    del self.mock_sessions[token]
            return True
        except Exception as e:
            print(f"❌ Error deleting session: {e}")
            return False

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
    
    def initialize_transaction(self, email: str, amount: int, metadata: Dict = None, channel: str = None) -> Dict[str, Any]:
        """Initialize a Paystack transaction"""
        url = f"{self.base_url}/transaction/initialize"
        payload = {
            'email': email,
            'amount': amount * 100,
            'metadata': metadata or {},
            'currency': 'NGN'
        }
        
        if channel:
            payload['channels'] = [channel]
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get('status'):
                return {'status': True, 'data': result['data']}
            else:
                error_msg = result.get('message', 'Unknown Paystack error')
                return {'status': False, 'message': error_msg}
                
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': f'Paystack API error: {str(e)}'}
        except Exception as e:
            return {'status': False, 'message': f'Unexpected error: {str(e)}'}
    
    def verify_transaction(self, reference: str) -> Dict[str, Any]:
        """Verify a Paystack transaction"""
        url = f"{self.base_url}/transaction/verify/{reference}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get('status') and result['data']['status'] == 'success':
                return {'status': True, 'data': result['data']}
            else:
                error_msg = result.get('message', 'Transaction verification failed')
                return {'status': False, 'message': error_msg}
                
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': f'Paystack verification error: {str(e)}'}
        except Exception as e:
            return {'status': False, 'message': f'Unexpected verification error: {str(e)}'}

# ==================== VTPASS SERVICE ====================

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
    
    def make_request(self, endpoint, method="POST", data=None):
        """Generic VTPass request"""
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers, timeout=30)
            else:
                response = requests.post(url, headers=self.headers, json=data, timeout=30)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            return {'code': '099', 'response_description': 'VTPass API timeout'}
        except requests.exceptions.ConnectionError:
            return {'code': '099', 'response_description': 'VTPass API connection error'}
        except Exception as e:
            return {'code': '099', 'response_description': f'VTPass error: {str(e)}'}
    
    def pay(self, service_id, billers_code, variation_code, amount, phone=None):
        """Process VTPass payment"""
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
        
        return self.make_request("pay", "POST", payload)

# ==================== TERMII SERVICE ====================

class TermiiService:
    def __init__(self):
        self.api_key = Config.TERMII_API_KEY
        self.base_url = "https://api.ng.termii.com/api"
    
    def send_sms(self, phone: str, message: str, sender_id: str = "Cheap4uApp") -> Dict[str, Any]:
        """Send SMS via Termii"""
        if not self.api_key or self.api_key == 'test_termii_key':
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
            return {'status': 'error', 'message': str(e)}

# ==================== UTILITY FUNCTIONS ====================

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

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def is_admin(user_email):
    """Check if user is admin"""
    return user_email in Config.ADMIN_EMAILS

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

def generate_otp_code():
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

# ==================== RESPONSE HANDLER ====================

def handle_vtpass_response_with_profit(result, request_data, service_type, base_amount, selling_amount, expected_profit):
    """Handle VTPass response with profit tracking"""
    try:
        user_email = request_data.get('user_email')
        user = None
        transaction_deducted = False
        
        # 1. Deduct from user wallet
        if user_email:
            user = firebase_client.get_user_by_email(user_email)
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
            success = firebase_client.update_user_wallet(user['id'], -selling_amount)
            if not success:
                return jsonify({'status': 'error', 'message': 'Insufficient wallet balance'}), 400
            
            transaction_deducted = True
        
        # 2. Handle VTPass response
        if result.get('code') == '000':
            # Add profit to profit wallet
            firebase_client.update_profit_wallet(expected_profit)
            
            # Create transaction record
            tx_data = {
                'user_email': user_email,
                'type': service_type,
                'service_type': service_type,
                'service_id': request_data.get('service_id'),
                'billers_code': request_data.get('billers_code'),
                'variation_code': request_data.get('variation_code'),
                'base_amount': base_amount,
                'selling_amount': selling_amount,
                'profit_amount': expected_profit,
                'status': 'success',
                'vtpass_response': result,
                'created_at': datetime.now().isoformat()
            }
            tx_id = firebase_client.create_transaction(tx_data)
            
            # Record profit ledger entry
            ledger_data = {
                'transaction_id': tx_id,
                'user_email': user_email,
                'service_type': service_type,
                'base_amount': base_amount,
                'selling_amount': selling_amount,
                'profit_amount': expected_profit,
                'type': f'{service_type}_profit',
                'status': 'completed',
                'created_at': datetime.now().isoformat()
            }
            firebase_client.create_profit_ledger_entry(ledger_data)
            
            response_data = {
                **result,
                'transaction_id': tx_id,
                'profit_amount': expected_profit,
                'base_amount': base_amount,
                'selling_amount': selling_amount
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
            # Refund user on failure
            if transaction_deducted and user:
                firebase_client.update_user_wallet(user['id'], selling_amount)
            
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({
                'status': 'error',
                'message': f'VTPass Error: {error_msg}',
                'data': result
            }), 400
            
    except Exception as e:
        print(f"💥 Profit handling error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Transaction processing failed: {str(e)}'}), 500

# ==================== FLASK APP ====================

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=['*'])

# Initialize services
print("🔄 Initializing services...")
firebase_client = FirebaseClient.get_instance()
paystack_service = PaystackService()
vtpass_service = VTPassService()
termii_service = TermiiService()
print("✅ All services initialized successfully!")

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

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Complete user registration with OTP verification"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Validate email
        email = data['email'].lower().strip()
        if not validate_email(email):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Validate phone
        phone = data['phone'].strip()
        if not validate_phone(phone):
            return jsonify({'status': 'error', 'message': 'Invalid phone number. Use 11-digit Nigerian format'}), 400
        
        # Validate password
        password = data['password']
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
        
        # Check if user already exists
        existing_user = firebase_client.get_user_by_email(email)
        if existing_user:
            return jsonify({'status': 'error', 'message': 'User with this email already exists'}), 400
        
        # Check if phone already exists
        existing_phone_user = firebase_client.get_user_by_phone(phone)
        if existing_phone_user:
            return jsonify({'status': 'error', 'message': 'User with this phone number already exists'}), 400
        
        # Generate user ID
        user_id = str(uuid.uuid4())
        
        # Generate OTP
        otp_code = generate_otp_code()
        otp_expiry = datetime.now() + timedelta(minutes=5)
        
        # Create user data
        user_data = {
            'id': user_id,
            'name': data['name'].strip(),
            'email': email,
            'phone': phone,
            'password': hash_password(password),
            'wallet_balance': 0.0,
            'referral_balance': 0.0,
            'is_verified': False,
            'is_premium': False,
            'joined_date': datetime.now().strftime("%Y-%m-%d"),
            'last_login': None,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        # Create user
        success = firebase_client.create_user(user_id, user_data)
        if not success:
            return jsonify({'status': 'error', 'message': 'Failed to create user account'}), 500
        
        # Store OTP
        otp_data = {
            'user_id': user_id,
            'email': email,
            'phone': phone,
            'otp_code': otp_code,
            'expiry': otp_expiry.isoformat(),
            'verified': False,
            'created_at': datetime.now().isoformat()
        }
        
        firebase_client.create_otp_record(user_id, otp_data)
        
        # Send OTP via SMS
        sms_message = f"Your Cheap4U verification code is: {otp_code}. Valid for 5 minutes."
        sms_result = termii_service.send_sms(phone, sms_message)
        
        print(f"✅ User registered: {user_id}, OTP: {otp_code}")
        
        return jsonify({
            'status': 'success',
            'message': 'Registration successful. Please verify your account with the OTP sent to your phone.',
            'data': {
                'user_id': user_id,
                'email': email,
                'phone': phone,
                'mock_otp': otp_code if not firebase_client.root_ref else None
            }
        }), 201
        
    except Exception as e:
        print(f"💥 Registration error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP for account activation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        user_id = data.get('user_id')
        otp_code = data.get('otp_code')
        
        if not user_id or not otp_code:
            return jsonify({'status': 'error', 'message': 'User ID and OTP code are required'}), 400
        
        # Get OTP record
        otp_record = firebase_client.get_otp_record(user_id)
        if not otp_record:
            return jsonify({'status': 'error', 'message': 'OTP not found or expired'}), 400
        
        # Check if already verified
        if otp_record.get('verified', False):
            return jsonify({'status': 'error', 'message': 'OTP already verified'}), 400
        
        # Check expiry
        expiry_str = otp_record.get('expiry')
        if expiry_str:
            expiry_time = datetime.fromisoformat(expiry_str)
            if datetime.now() > expiry_time:
                return jsonify({'status': 'error', 'message': 'OTP has expired'}), 400
        
        # Verify OTP code
        if otp_record.get('otp_code') != otp_code:
            return jsonify({'status': 'error', 'message': 'Invalid OTP code'}), 400
        
        # Mark OTP as verified
        firebase_client.update_otp_record(user_id, {'verified': True})
        
        # Activate user account
        firebase_client.update_user(user_id, {
            'is_verified': True,
            'updated_at': datetime.now().isoformat()
        })
        
        # Generate session token
        session_token = str(uuid.uuid4())
        session_data = {
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
        }
        
        firebase_client.create_session(session_token, session_data)
        
        # Get user data
        user = firebase_client.get_user(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Remove sensitive data
        user_response = {k: v for k, v in user.items() if k not in ['password', 'otp_code']}
        
        print(f"✅ Account verified: {user['email']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Account verified successfully',
            'data': {
                'user': user_response,
                'session_token': session_token,
                'expires_in': 604800
            }
        })
        
    except Exception as e:
        print(f"💥 OTP verification error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'OTP verification failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """User login"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        if not validate_email(email):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        
        # Find user
        user = firebase_client.get_user_by_email(email)
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Check if user is verified
        if not user.get('is_verified', False):
            return jsonify({
                'status': 'error',
                'message': 'Account not verified. Please verify your email/phone first.',
                'requires_verification': True,
                'user_id': user['id']
            }), 401
        
        # Verify password
        hashed_input_password = hash_password(data['password'])
        if user.get('password') != hashed_input_password:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # Update last login
        firebase_client.update_user(user['id'], {
            'last_login': datetime.now().isoformat()
        })
        
        # Generate session token
        session_token = str(uuid.uuid4())
        session_data = {
            'user_id': user['id'],
            'email': user['email'],
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
        }
        
        firebase_client.create_session(session_token, session_data)
        
        # Remove sensitive data
        user_response = {k: v for k, v in user.items() if k not in ['password', 'otp_code']}
        
        print(f"✅ User logged in: {user['email']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': user_response,
                'session_token': session_token,
                'expires_in': 604800
            }
        })
        
    except Exception as e:
        print(f"💥 Login error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP code"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User ID is required'}), 400
        
        # Get user data
        user = firebase_client.get_user(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Check if already verified
        if user.get('is_verified', False):
            return jsonify({'status': 'error', 'message': 'Account already verified'}), 400
        
        # Generate new OTP
        new_otp = generate_otp_code()
        new_expiry = datetime.now() + timedelta(minutes=5)
        
        # Update OTP record
        otp_data = {
            'otp_code': new_otp,
            'expiry': new_expiry.isoformat(),
            'verified': False,
            'updated_at': datetime.now().isoformat()
        }
        
        firebase_client.update_otp_record(user_id, otp_data)
        
        # Send new OTP
        sms_message = f"Your Cheap4U verification code is: {new_otp}. Valid for 5 minutes."
        sms_result = termii_service.send_sms(user['phone'], sms_message)
        
        print(f"✅ OTP resent: {user['email']} - {new_otp}")
        
        return jsonify({
            'status': 'success',
            'message': 'OTP resent successfully',
            'data': {
                'user_id': user_id,
                'email': user['email'],
                'phone': user['phone'],
                'mock_otp': new_otp if not firebase_client.root_ref else None
            }
        })
        
    except Exception as e:
        print(f"💥 OTP resend error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'OTP resend failed: {str(e)}'}), 500

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
            channel=data.get('channel')
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
            amount = paystack_data['amount'] / 100
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
            
            # Credit user wallet
            if user_email and user_email != 'unknown':
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    success = firebase_client.update_user_wallet(user['id'], amount)
                    if success:
                        print(f"💰 Credited ₦{amount} to {user_email}")
                        
                        # Add profit for wallet funding
                        funding_profit = amount * 0.015
                        firebase_client.update_profit_wallet(funding_profit)
                        
                        # Record funding profit
                        ledger_data = {
                            'transaction_id': transaction_id,
                            'user_email': user_email,
                            'service_type': 'wallet_funding',
                            'amount': amount,
                            'profit_amount': funding_profit,
                            'rate_used': 0.015,
                            'status': 'completed',
                            'created_at': datetime.now().isoformat()
                        }
                        firebase_client.create_profit_ledger_entry(ledger_data)
                        
                        print(f"💰 Funding profit: ₦{funding_profit} from {user_email}")
            
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

# ==================== VTPASS ROUTES ====================

@app.route('/api/vtpass/airtime', methods=['POST'])
def purchase_airtime():
    """Purchase airtime with profitable pricing"""
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
        
        # Get original amount and calculate profitable price
        original_amount = float(data['amount'])
        profitable_amount = PricingConfig.calculate_selling_price(original_amount, 'airtime')
        profit_amount, final_amount = PricingConfig.calculate_profit_amount(
            profitable_amount, original_amount, 'airtime'
        )
        
        print(f"💰 Airtime Pricing: VTPass={original_amount}, Sell={final_amount}, Profit={profit_amount}")
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['airtime'][network]
        
        # Process with VTPass
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['phone'],
            variation_code=service_id,
            amount=original_amount,
            phone=data['phone']
        )
        
        # Handle response with profitable pricing
        return handle_vtpass_response_with_profit(
            result, data, 'airtime', original_amount, final_amount, profit_amount
        )
        
    except Exception as e:
        print(f"💥 Airtime purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Airtime purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/data', methods=['POST'])
def purchase_data():
    """Purchase data with profitable pricing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        print(f"📱 Data purchase request: {data}")
        
        # Validate required fields
        required_fields = ['network', 'phone', 'plan_code', 'base_price', 'selling_price']
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
        
        # Get prices from frontend
        base_price = float(data['base_price'])
        selling_price = float(data['selling_price'])
        profit_amount = selling_price - base_price
        
        print(f"💰 Data Pricing: VTPass={base_price}, Sell={selling_price}, Profit={profit_amount}")
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['data'][network]
        
        # Process with VTPass
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['phone'],
            variation_code=data['plan_code'],
            amount=base_price,
            phone=data['phone']
        )
        
        return handle_vtpass_response_with_profit(
            result, data, 'data', base_price, selling_price, profit_amount
        )
        
    except Exception as e:
        print(f"💥 Data purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Data purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/electricity', methods=['POST'])
def purchase_electricity():
    """Purchase electricity with profitable pricing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        print(f"⚡ Electricity purchase request: {data}")
        
        # Validate required fields
        required_fields = ['disco', 'meter_number', 'meter_type', 'base_amount', 'selling_amount']
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
        
        # Get prices
        base_amount = float(data['base_amount'])
        selling_amount = float(data['selling_amount'])
        profit_amount = selling_amount - base_amount
        
        print(f"💰 Electricity Pricing: VTPass={base_amount}, Sell={selling_amount}, Profit={profit_amount}")
        
        # Get service ID and variation code
        service_id = Config.VTPASS_SERVICE_IDS['electricity'][disco]
        meter_type = data['meter_type'].lower()
        variation_code = Config.VTPASS_VARIATION_CODES['electricity'].get(meter_type, 'prepaid')
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['meter_number'],
            variation_code=variation_code,
            amount=base_amount,
            phone=data.get('phone', '')
        )
        
        return handle_vtpass_response_with_profit(
            result, data, 'electricity', base_amount, selling_amount, profit_amount
        )
        
    except Exception as e:
        print(f"💥 Electricity purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Electricity purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/cable-tv', methods=['POST'])
def purchase_cable_tv():
    """Purchase cable TV with profitable pricing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        print(f"📺 Cable TV purchase request: {data}")
        
        # Validate required fields
        required_fields = ['provider', 'smartcard_number', 'package_code', 'base_price', 'selling_price']
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
        
        # Get prices
        base_price = float(data['base_price'])
        selling_price = float(data['selling_price'])
        profit_amount = selling_price - base_price
        
        print(f"💰 Cable TV Pricing: VTPass={base_price}, Sell={selling_price}, Profit={profit_amount}")
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['cable_tv'][provider]
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=data['smartcard_number'],
            variation_code=data['package_code'],
            amount=base_price,
            phone=data.get('phone', '')
        )
        
        return handle_vtpass_response_with_profit(
            result, data, 'cable_tv', base_price, selling_price, profit_amount
        )
        
    except Exception as e:
        print(f"💥 Cable TV purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Cable TV purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/exam-pins', methods=['POST'])
def purchase_exam_pins():
    """Purchase exam pins with profitable pricing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
        
        print(f"🎓 Exam PIN purchase request: {data}")
        
        # Validate required fields
        required_fields = ['exam_type', 'quantity', 'base_price', 'selling_price']
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
        
        # Get prices
        base_price = float(data['base_price'])
        selling_price = float(data['selling_price'])
        profit_amount = selling_price - base_price
        
        print(f"💰 Exam PIN Pricing: VTPass={base_price}, Sell={selling_price}, Profit={profit_amount}")
        
        # Get service ID and variation code
        service_id = Config.VTPASS_SERVICE_IDS['exam_pins'][exam_type]
        variation_code = Config.VTPASS_VARIATION_CODES['exam_pins'][exam_type]
        
        # For exam pins, billersCode can be unique
        billers_code = f"exam_{int(datetime.now().timestamp())}"
        
        result = vtpass_service.pay(
            service_id=service_id,
            billers_code=billers_code,
            variation_code=variation_code,
            amount=base_price,
            phone=data.get('phone', '')
        )
        
        return handle_vtpass_response_with_profit(
            result, data, 'exam_pins', base_price, selling_price, profit_amount
        )
        
    except Exception as e:
        print(f"💥 Exam PIN purchase error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Exam PIN purchase failed: {str(e)}'}), 500

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/profit', methods=['GET'])
def get_profit_summary():
    """Admin-only profit summary"""
    try:
        user_email = request.args.get('user_email')
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        if firebase_client.root_ref:
            profit_ref = firebase_client.root_ref.child('profit_wallet')
            profit_data = profit_ref.get() or {
                'total_available': 0.0,
                'total_earned': 0.0,
                'total_withdrawn': 0.0,
                'transaction_count': 0
            }
        else:
            profit_data = firebase_client.mock_profit_wallet
        
        return jsonify({
            'status': 'success',
            'data': profit_data
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/profit/withdraw', methods=['POST'])
def withdraw_profit():
    """Complete profit withdrawal with bank transfer"""
    try:
        data = request.get_json()
        user_email = data.get('user_email')
        amount = data.get('amount')
        bank_details = data.get('bank_details')
        
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        if not amount or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Valid amount required'}), 400
        
        if amount < 1000:
            return jsonify({'status': 'error', 'message': 'Minimum withdrawal is ₦1,000'}), 400
        
        if amount > 500000:
            return jsonify({'status': 'error', 'message': 'Maximum withdrawal is ₦500,000'}), 400
        
        if not bank_details or not all([
            bank_details.get('bank_name'),
            bank_details.get('account_number'),
            bank_details.get('account_name')
        ]):
            return jsonify({'status': 'error', 'message': 'Complete bank details required'}), 400
        
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
        
        # Process bank transfer (mock for now)
        transfer_result = {
            'status': True,
            'message': 'Transfer initiated successfully',
            'reference': f'tx_{int(datetime.now().timestamp())}'
        }
        
        if transfer_result.get('status'):
            # Deduct from profit wallet
            success = firebase_client.update_profit_wallet(amount, "withdrawal")
            if not success:
                return jsonify({'status': 'error', 'message': 'Failed to update profit wallet'}), 400
            
            # Record withdrawal transaction
            withdrawal_id = f"wd_{int(datetime.now().timestamp())}"
            withdrawal_data = {
                'id': withdrawal_id,
                'user_email': user_email,
                'amount': amount,
                'bank_details': bank_details,
                'status': 'completed',
                'transfer_reference': transfer_result.get('reference'),
                'previous_balance': available_balance,
                'new_balance': available_balance - amount,
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
            
            if firebase_client.root_ref:
                firebase_client.root_ref.child(f'withdrawals/{withdrawal_id}').set(withdrawal_data)
            else:
                firebase_client.mock_withdrawals[withdrawal_id] = withdrawal_data
            
            print(f"💸 Profit withdrawal completed: ₦{amount} by {user_email}")
            
            return jsonify({
                'status': 'success',
                'message': 'Profit withdrawal completed successfully',
                'data': {
                    'withdrawal_id': withdrawal_id,
                    'amount': amount,
                    'transfer_reference': transfer_result.get('reference'),
                    'previous_balance': available_balance,
                    'new_balance': available_balance - amount
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Bank transfer failed: {transfer_result.get("message")}'
            }), 400
            
    except Exception as e:
        print(f"💥 Withdrawal error: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Withdrawal failed: {str(e)}'}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    print(f"💥 Internal server error: {error}")
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
    print(f"💰 Profitable Pricing: ✅ ENABLED")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
