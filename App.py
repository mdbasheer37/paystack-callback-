import os
import json
import hmac
import hashlib
import requests
import uuid
import random
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("🚀 VTU Backend Initialization...")

# ==================== CONFIGURATION ====================

class Config:
    """Application configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Paystack
    PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', 'sk_test_xxxxxxxxxxxxxx')
    PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', 'pk_test_xxxxxxxxxxxxxx')
    PAYSTACK_BASE_URL = 'https://api.paystack.co'
    
    # VTPass
    VTPASS_API_KEY = os.getenv('VTPASS_API_KEY', '')
    VTPASS_SECRET_KEY = os.getenv('VTPASS_SECRET_KEY', '')
    VTPASS_BASE_URL = 'https://vtpass.com/api'
    
    # Termii
    TERMII_API_KEY = os.getenv('TERMII_API_KEY', '')
    
    # Firebase - Use environment variable for Render deployment
    FIREBASE_CONFIG = os.getenv('FIREBASE_CONFIG')
    
    # Admin emails
    ADMIN_EMAILS = ['admin@cheap4u.com', 'muhammadibrahim376@gmail.com']
    
    # Service IDs
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

# ==================== PRICING CONFIG ====================

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
        selling_price = round(selling_price / 10) * 10  # Round to nearest 10
        
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

# ==================== DATABASE CLIENT ====================

class DatabaseClient:
    """Database client for storing data"""
    
    def __init__(self):
        self.users = {}
        self.transactions = {}
        self.profit_wallet = {
            'total_available': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'transaction_count': 0,
            'last_updated': datetime.now().isoformat()
        }
        self.withdrawals = {}
        self.otp_records = {}
        self.sessions = {}
        self.referrals = {}
        print("🔧 Using in-memory database for development")
    
    def create_user(self, user_data):
        """Create a new user"""
        user_id = str(uuid.uuid4())
        user_data['id'] = user_id
        user_data['created_at'] = datetime.now().isoformat()
        user_data['updated_at'] = datetime.now().isoformat()
        self.users[user_id] = user_data
        return user_id
    
    def get_user_by_email(self, email):
        """Get user by email"""
        for user_id, user_data in self.users.items():
            if user_data.get('email', '').lower() == email.lower():
                user_data['id'] = user_id
                return user_data
        return None
    
    def get_user_by_phone(self, phone):
        """Get user by phone"""
        for user_id, user_data in self.users.items():
            if user_data.get('phone') == phone:
                user_data['id'] = user_id
                return user_data
        return None
    
    def get_user(self, user_id):
        """Get user by ID"""
        user_data = self.users.get(user_id)
        if user_data:
            user_data['id'] = user_id
        return user_data
    
    def update_user(self, user_id, updates):
        """Update user data"""
        if user_id in self.users:
            self.users[user_id].update(updates)
            self.users[user_id]['updated_at'] = datetime.now().isoformat()
            return True
        return False
    
    def update_user_wallet(self, user_id, amount):
        """Update user wallet balance"""
        if user_id in self.users:
            current_balance = self.users[user_id].get('wallet_balance', 0.0)
            new_balance = max(0.0, float(current_balance) + amount)
            self.users[user_id]['wallet_balance'] = new_balance
            print(f"💰 Updated wallet for {user_id}: {current_balance} -> {new_balance}")
            return True
        return False
    
    def create_transaction(self, transaction_data):
        """Create transaction record"""
        tx_id = f"tx_{int(datetime.now().timestamp())}"
        transaction_data['id'] = tx_id
        transaction_data['created_at'] = datetime.now().isoformat()
        self.transactions[tx_id] = transaction_data
        return tx_id
    
    def get_transaction_by_reference(self, reference):
        """Get transaction by reference"""
        for tx_id, tx_data in self.transactions.items():
            if tx_data.get('payment_reference') == reference:
                tx_data['id'] = tx_id
                return tx_data
        return None
    
    def update_transaction(self, transaction_id, updates):
        """Update transaction"""
        if transaction_id in self.transactions:
            self.transactions[transaction_id].update(updates)
            return True
        return False
    
    def create_otp_record(self, otp_data):
        """Create OTP record"""
        otp_id = f"otp_{int(datetime.now().timestamp())}"
        otp_data['id'] = otp_id
        self.otp_records[otp_id] = otp_data
        return otp_id
    
    def get_otp_record(self, user_id):
        """Get OTP record by user ID"""
        for otp_id, otp_data in self.otp_records.items():
            if otp_data.get('user_id') == user_id:
                return otp_data
        return None
    
    def update_otp_record(self, user_id, updates):
        """Update OTP record"""
        for otp_id, otp_data in self.otp_records.items():
            if otp_data.get('user_id') == user_id:
                self.otp_records[otp_id].update(updates)
                return True
        return False
    
    def create_session(self, token, session_data):
        """Create session"""
        self.sessions[token] = session_data
        return True
    
    def get_session(self, token):
        """Get session"""
        return self.sessions.get(token)
    
    def delete_session(self, token):
        """Delete session"""
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False
    
    def update_profit_wallet(self, amount, transaction_type="profit"):
        """Update profit wallet"""
        if transaction_type == "profit":
            self.profit_wallet['total_available'] += amount
            self.profit_wallet['total_earned'] += amount
            self.profit_wallet['transaction_count'] += 1
        elif transaction_type == "withdrawal":
            self.profit_wallet['total_available'] -= amount
            self.profit_wallet['total_withdrawn'] += amount
        
        self.profit_wallet['total_available'] = max(0.0, self.profit_wallet['total_available'])
        self.profit_wallet['last_updated'] = datetime.now().isoformat()
        
        print(f"💰 Profit Wallet: {transaction_type} ₦{amount}. Available: ₦{self.profit_wallet['total_available']}")
        return True
    
    def create_withdrawal(self, withdrawal_data):
        """Create withdrawal record"""
        wd_id = f"wd_{int(datetime.now().timestamp())}"
        withdrawal_data['id'] = wd_id
        self.withdrawals[wd_id] = withdrawal_data
        return wd_id

# ==================== PAYSTACK SERVICE ====================

class PaystackService:
    """Paystack payment service"""
    
    def __init__(self):
        self.secret_key = Config.PAYSTACK_SECRET_KEY
        self.public_key = Config.PAYSTACK_PUBLIC_KEY
        self.base_url = Config.PAYSTACK_BASE_URL
        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }
        print(f"🔧 Paystack Service Initialized: {self.base_url}")
    
    def initialize_transaction(self, email, amount, metadata=None, channel=None, callback_url=None):
        """Initialize a transaction"""
        url = f"{self.base_url}/transaction/initialize"
        payload = {
            'email': email,
            'amount': amount * 100,
            'metadata': metadata or {},
            'currency': 'NGN'
        }
        
        if channel:
            payload['channels'] = [channel]
        if callback_url:
            payload['callback_url'] = callback_url
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get('status'):
                return {'status': True, 'data': result['data']}
            else:
                error_msg = result.get('message', 'Unknown error')
                return {'status': False, 'message': error_msg}
                
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': f'API error: {str(e)}'}
        except Exception as e:
            return {'status': False, 'message': f'Unexpected error: {str(e)}'}
    
    def verify_transaction(self, reference):
        """Verify a transaction"""
        url = f"{self.base_url}/transaction/verify/{reference}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get('status') and result['data']['status'] == 'success':
                return {'status': True, 'data': result['data']}
            else:
                error_msg = result.get('message', 'Verification failed')
                return {'status': False, 'message': error_msg}
                
        except requests.exceptions.RequestException as e:
            return {'status': False, 'message': f'API error: {str(e)}'}
        except Exception as e:
            return {'status': False, 'message': f'Unexpected error: {str(e)}'}

# ==================== VTPASS SERVICE ====================

class VTPassService:
    """VTPass service integration"""
    
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
    
    def pay(self, service_id, billers_code, variation_code, amount, phone=None):
        """Process payment"""
        url = f"{self.base_url}/pay"
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code,
            'variation_code': variation_code,
            'amount': amount,
            'phone': phone or '',
            'request_id': f"req_{int(datetime.now().timestamp())}"
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'code': '099', 'response_description': f'API error: {str(e)}'}
        except Exception as e:
            return {'code': '099', 'response_description': f'Unexpected error: {str(e)}'}
    
    def verify_service(self, service_id, billers_code):
        """Verify service"""
        url = f"{self.base_url}/merchant-verify"
        payload = {
            'serviceID': service_id,
            'billersCode': billers_code
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except:
            return None

# ==================== TERMII SERVICE ====================

class TermiiService:
    """Termii SMS service"""
    
    def __init__(self):
        self.api_key = Config.TERMII_API_KEY
        self.base_url = "https://api.ng.termii.com/api"
    
    def send_sms(self, phone, message, sender_id="Cheap4uApp"):
        """Send SMS"""
        if not self.api_key or self.api_key == 'test_termii_key':
            print(f"🔧 Mock SMS sent to {phone}: {message}")
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
            return response.json()
        except:
            return {'status': 'error', 'message': 'Failed to send SMS'}

# ==================== UTILITY FUNCTIONS ====================

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    """Validate Nigerian phone number"""
    if not phone:
        return False
    return len(phone) == 11 and phone.isdigit() and phone.startswith(('070', '080', '081', '090', '091'))

def validate_amount(amount):
    """Validate amount"""
    try:
        if isinstance(amount, (int, float)):
            amount_float = float(amount)
        else:
            amount_float = float(str(amount).replace('₦', '').replace(',', '').strip())
        
        if amount_float <= 0:
            return False, 0
        return True, amount_float
    except:
        return False, 0

def hash_password(password):
    """Hash password"""
    return hashlib.sha256(password.encode()).hexdigest()

def is_admin(user_email):
    """Check if user is admin"""
    return user_email in Config.ADMIN_EMAILS

def generate_otp():
    """Generate OTP"""
    return str(random.randint(100000, 999999))

# ==================== FLASK APP ====================

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize services
db = DatabaseClient()
paystack = PaystackService()
vtpass = VTPassService()
termii = TermiiService()

print("✅ All services initialized successfully!")
print(f"🔑 Paystack: {'✅ Configured' if paystack.secret_key else '❌ Not Configured'}")
print(f"🔧 VTPass: {'✅ Configured' if vtpass.api_key else '❌ Not Configured'}")
print(f"💰 Profitable Pricing: ✅ ENABLED")

# ==================== ROUTES ====================

@app.route('/')
def home():
    return jsonify({
        'message': '🚀 VTU Backend API is running!',
        'status': 'active',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'VTU Backend API',
        'timestamp': datetime.now().isoformat()
    })

# ==================== AUTHENTICATION ====================

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """User registration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate required fields
        required = ['name', 'email', 'phone', 'password']
        missing = [field for field in required if not data.get(field)]
        if missing:
            return jsonify({'status': 'error', 'message': f'Missing: {", ".join(missing)}'}), 400
        
        # Validate email
        email = data['email'].lower().strip()
        if not validate_email(email):
            return jsonify({'status': 'error', 'message': 'Invalid email'}), 400
        
        # Validate phone
        phone = data['phone'].strip()
        if not validate_phone(phone):
            return jsonify({'status': 'error', 'message': 'Invalid phone'}), 400
        
        # Check if user exists
        if db.get_user_by_email(email):
            return jsonify({'status': 'error', 'message': 'Email already registered'}), 400
        
        if db.get_user_by_phone(phone):
            return jsonify({'status': 'error', 'message': 'Phone already registered'}), 400
        
        # Hash password
        hashed_pw = hash_password(data['password'])
        
        # Generate OTP
        otp_code = generate_otp()
        
        # Create user
        user_data = {
            'name': data['name'].strip(),
            'email': email,
            'phone': phone,
            'password': hashed_pw,
            'wallet_balance': 0.0,
            'is_verified': False,
            'joined_date': datetime.now().strftime("%Y-%m-%d"),
            'created_at': datetime.now().isoformat()
        }
        
        user_id = db.create_user(user_data)
        
        # Store OTP
        otp_data = {
            'user_id': user_id,
            'otp_code': otp_code,
            'expiry': (datetime.now() + timedelta(minutes=5)).isoformat(),
            'verified': False
        }
        db.create_otp_record(otp_data)
        
        # Send OTP
        sms_message = f"Your Cheap4U verification code: {otp_code}. Valid for 5 minutes."
        termii.send_sms(phone, sms_message)
        
        return jsonify({
            'status': 'success',
            'message': 'Registration successful. Verify with OTP.',
            'data': {
                'user_id': user_id,
                'otp_code': otp_code  # For development/testing
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        otp_code = data.get('otp_code')
        
        if not user_id or not otp_code:
            return jsonify({'status': 'error', 'message': 'User ID and OTP required'}), 400
        
        # Get OTP record
        otp_record = db.get_otp_record(user_id)
        if not otp_record:
            return jsonify({'status': 'error', 'message': 'OTP not found'}), 400
        
        # Check expiry
        expiry = datetime.fromisoformat(otp_record.get('expiry', ''))
        if datetime.now() > expiry:
            return jsonify({'status': 'error', 'message': 'OTP expired'}), 400
        
        # Verify OTP
        if otp_record.get('otp_code') != otp_code:
            return jsonify({'status': 'error', 'message': 'Invalid OTP'}), 400
        
        # Mark as verified
        db.update_otp_record(user_id, {'verified': True})
        
        # Update user
        db.update_user(user_id, {
            'is_verified': True,
            'verified_at': datetime.now().isoformat()
        })
        
        return jsonify({
            'status': 'success',
            'message': 'Account verified successfully'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Verification failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """User login"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        email = data.get('email', '').lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400
        
        # Get user
        user = db.get_user_by_email(email)
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
        
        # Verify password
        if user.get('password') != hash_password(password):
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
        
        # Check if verified
        if not user.get('is_verified', False):
            return jsonify({
                'status': 'error',
                'message': 'Account not verified',
                'requires_verification': True,
                'user_id': user['id']
            }), 401
        
        # Generate session token
        session_token = str(uuid.uuid4())
        session_data = {
            'user_id': user['id'],
            'email': user['email'],
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
        }
        db.create_session(session_token, session_data)
        
        # Remove sensitive data
        user_response = {k: v for k, v in user.items() if k not in ['password']}
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': user_response,
                'session_token': session_token
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}'}), 500

# ==================== VTPASS SERVICES ====================

@app.route('/api/vtpass/airtime', methods=['POST'])
def purchase_airtime():
    """Purchase airtime"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate
        network = data.get('network')
        phone = data.get('phone')
        amount = data.get('amount')
        
        if not network or not phone or not amount:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        if not validate_phone(phone):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['airtime'].get(network)
        if not service_id:
            return jsonify({'status': 'error', 'message': 'Unsupported network'}), 400
        
        # Calculate profitable price
        base_amount = float(amount)
        selling_amount = PricingConfig.calculate_selling_price(base_amount, 'airtime')
        profit_amount, final_amount = PricingConfig.calculate_profit_amount(
            selling_amount, base_amount, 'airtime'
        )
        
        print(f"💰 Airtime: Base={base_amount}, Sell={final_amount}, Profit={profit_amount}")
        
        # Process with VTPass
        result = vtpass.pay(
            service_id=service_id,
            billers_code=phone,
            variation_code=service_id,
            amount=base_amount,
            phone=phone
        )
        
        # Handle response
        if result.get('code') == '000':
            # Success - update profit
            db.update_profit_wallet(profit_amount)
            
            # Record transaction
            tx_data = {
                'user_email': data.get('user_email'),
                'type': 'airtime',
                'network': network,
                'phone': phone,
                'base_amount': base_amount,
                'selling_amount': final_amount,
                'profit_amount': profit_amount,
                'status': 'success',
                'vtpass_response': result
            }
            tx_id = db.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Airtime purchase successful',
                'data': {
                    'transaction_id': tx_id,
                    'profit_amount': profit_amount,
                    'vtpass_response': result
                }
            })
        else:
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Airtime purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/data', methods=['POST'])
def purchase_data():
    """Purchase data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate
        network = data.get('network')
        phone = data.get('phone')
        plan_code = data.get('plan_code')
        base_price = data.get('base_price')
        selling_price = data.get('selling_price')
        
        if not all([network, phone, plan_code, base_price, selling_price]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        if not validate_phone(phone):
            return jsonify({'status': 'error', 'message': 'Invalid phone number'}), 400
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['data'].get(network)
        if not service_id:
            return jsonify({'status': 'error', 'message': 'Unsupported network'}), 400
        
        base_amount = float(base_price)
        selling_amount = float(selling_price)
        profit_amount = selling_amount - base_amount
        
        print(f"💰 Data: Base={base_amount}, Sell={selling_amount}, Profit={profit_amount}")
        
        # Process with VTPass
        result = vtpass.pay(
            service_id=service_id,
            billers_code=phone,
            variation_code=plan_code,
            amount=base_amount,
            phone=phone
        )
        
        if result.get('code') == '000':
            # Success - update profit
            db.update_profit_wallet(profit_amount)
            
            # Record transaction
            tx_data = {
                'user_email': data.get('user_email'),
                'type': 'data',
                'network': network,
                'phone': phone,
                'plan_code': plan_code,
                'base_amount': base_amount,
                'selling_amount': selling_amount,
                'profit_amount': profit_amount,
                'status': 'success',
                'vtpass_response': result
            }
            tx_id = db.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Data purchase successful',
                'data': {
                    'transaction_id': tx_id,
                    'profit_amount': profit_amount
                }
            })
        else:
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Data purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/electricity', methods=['POST'])
def purchase_electricity():
    """Purchase electricity"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate
        disco = data.get('disco')
        meter_number = data.get('meter_number')
        meter_type = data.get('meter_type')
        base_amount = data.get('base_amount')
        selling_amount = data.get('selling_amount')
        
        if not all([disco, meter_number, meter_type, base_amount, selling_amount]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['electricity'].get(disco)
        if not service_id:
            return jsonify({'status': 'error', 'message': 'Unsupported disco'}), 400
        
        # Get variation code
        meter_type_lower = meter_type.lower()
        variation_code = Config.VTPASS_VARIATION_CODES['electricity'].get(meter_type_lower, 'prepaid')
        
        base_price = float(base_amount)
        sell_price = float(selling_amount)
        profit_amount = sell_price - base_price
        
        print(f"💰 Electricity: Base={base_price}, Sell={sell_price}, Profit={profit_amount}")
        
        # Process with VTPass
        result = vtpass.pay(
            service_id=service_id,
            billers_code=meter_number,
            variation_code=variation_code,
            amount=base_price,
            phone=data.get('phone', '')
        )
        
        if result.get('code') == '000':
            # Success - update profit
            db.update_profit_wallet(profit_amount)
            
            # Record transaction
            tx_data = {
                'user_email': data.get('user_email'),
                'type': 'electricity',
                'disco': disco,
                'meter_number': meter_number,
                'meter_type': meter_type,
                'base_amount': base_price,
                'selling_amount': sell_price,
                'profit_amount': profit_amount,
                'status': 'success',
                'vtpass_response': result,
                'token': result.get('content', {}).get('Token', '')
            }
            tx_id = db.create_transaction(tx_data)
            
            response_data = {
                'transaction_id': tx_id,
                'profit_amount': profit_amount
            }
            
            if result.get('content', {}).get('Token'):
                response_data['token'] = result['content']['Token']
                response_data['units'] = result['content'].get('Units')
            
            return jsonify({
                'status': 'success',
                'message': 'Electricity purchase successful',
                'data': response_data
            })
        else:
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Electricity purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/cable-tv', methods=['POST'])
def purchase_cable_tv():
    """Purchase cable TV"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate
        provider = data.get('provider')
        smartcard_number = data.get('smartcard_number')
        package_code = data.get('package_code')
        base_price = data.get('base_price')
        selling_price = data.get('selling_price')
        
        if not all([provider, smartcard_number, package_code, base_price, selling_price]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # Get service ID
        service_id = Config.VTPASS_SERVICE_IDS['cable_tv'].get(provider)
        if not service_id:
            return jsonify({'status': 'error', 'message': 'Unsupported provider'}), 400
        
        base_amount = float(base_price)
        sell_amount = float(selling_price)
        profit_amount = sell_amount - base_amount
        
        print(f"💰 Cable TV: Base={base_amount}, Sell={sell_amount}, Profit={profit_amount}")
        
        # Process with VTPass
        result = vtpass.pay(
            service_id=service_id,
            billers_code=smartcard_number,
            variation_code=package_code,
            amount=base_amount,
            phone=data.get('phone', '')
        )
        
        if result.get('code') == '000':
            # Success - update profit
            db.update_profit_wallet(profit_amount)
            
            # Record transaction
            tx_data = {
                'user_email': data.get('user_email'),
                'type': 'cable_tv',
                'provider': provider,
                'smartcard_number': smartcard_number,
                'package_code': package_code,
                'base_amount': base_amount,
                'selling_amount': sell_amount,
                'profit_amount': profit_amount,
                'status': 'success',
                'vtpass_response': result
            }
            tx_id = db.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Cable TV purchase successful',
                'data': {
                    'transaction_id': tx_id,
                    'profit_amount': profit_amount
                }
            })
        else:
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Cable TV purchase failed: {str(e)}'}), 500

@app.route('/api/vtpass/exam-pins', methods=['POST'])
def purchase_exam_pins():
    """Purchase exam pins"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Validate
        exam_type = data.get('exam_type')
        quantity = data.get('quantity')
        base_price = data.get('base_price')
        selling_price = data.get('selling_price')
        
        if not all([exam_type, quantity, base_price, selling_price]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # Validate exam type
        service_id = Config.VTPASS_SERVICE_IDS['exam_pins'].get(exam_type)
        if not service_id:
            return jsonify({'status': 'error', 'message': 'Unsupported exam type'}), 400
        
        # Validate quantity
        try:
            qty = int(quantity)
            if qty < 1 or qty > 10:
                return jsonify({'status': 'error', 'message': 'Quantity must be 1-10'}), 400
        except:
            return jsonify({'status': 'error', 'message': 'Invalid quantity'}), 400
        
        # Get variation code
        variation_code = Config.VTPASS_VARIATION_CODES['exam_pins'].get(exam_type)
        
        base_amount = float(base_price)
        sell_amount = float(selling_price)
        profit_amount = sell_amount - base_amount
        
        print(f"💰 Exam Pins: Base={base_amount}, Sell={sell_amount}, Profit={profit_amount}")
        
        # Generate billers code
        billers_code = f"exam_{int(datetime.now().timestamp())}"
        
        # Process with VTPass
        result = vtpass.pay(
            service_id=service_id,
            billers_code=billers_code,
            variation_code=variation_code,
            amount=base_amount,
            phone=data.get('phone', '')
        )
        
        if result.get('code') == '000':
            # Success - update profit
            db.update_profit_wallet(profit_amount)
            
            # Record transaction
            tx_data = {
                'user_email': data.get('user_email'),
                'type': 'exam_pins',
                'exam_type': exam_type,
                'quantity': qty,
                'base_amount': base_amount,
                'selling_amount': sell_amount,
                'profit_amount': profit_amount,
                'status': 'success',
                'vtpass_response': result
            }
            tx_id = db.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Exam PINs purchase successful',
                'data': {
                    'transaction_id': tx_id,
                    'profit_amount': profit_amount
                }
            })
        else:
            error_msg = result.get('response_description', 'VTPass payment failed')
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Exam PINs purchase failed: {str(e)}'}), 500

# ==================== PAYMENT ROUTES ====================

@app.route('/api/payment/initialize', methods=['POST'])
def initialize_payment():
    """Initialize payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        email = data.get('email')
        amount = data.get('amount')
        
        if not email or not amount:
            return jsonify({'status': 'error', 'message': 'Email and amount required'}), 400
        
        if not validate_email(email):
            return jsonify({'status': 'error', 'message': 'Invalid email'}), 400
        
        valid, amount_float = validate_amount(amount)
        if not valid:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        
        if amount_float < 100:
            return jsonify({'status': 'error', 'message': 'Minimum amount is ₦100'}), 400
        
        if amount_float > 500000:
            return jsonify({'status': 'error', 'message': 'Maximum amount is ₦500,000'}), 400
        
        # Prepare metadata
        metadata = data.get('metadata', {})
        metadata.update({
            'user_email': email,
            'service_type': data.get('service_type', 'wallet_funding')
        })
        
        # Initialize with Paystack
        result = paystack.initialize_transaction(
            email=email,
            amount=int(amount_float),
            metadata=metadata,
            channel=data.get('channel'),
            callback_url=data.get('callback_url')
        )
        
        if result.get('status'):
            # Record transaction
            tx_data = {
                'user_email': email,
                'amount': amount_float,
                'payment_reference': result['data']['reference'],
                'authorization_url': result['data']['authorization_url'],
                'status': 'pending',
                'type': data.get('service_type', 'wallet_funding'),
                'metadata': metadata
            }
            tx_id = db.create_transaction(tx_data)
            
            return jsonify({
                'status': 'success',
                'message': 'Payment initialized',
                'data': {
                    **result['data'],
                    'transaction_id': tx_id
                }
            })
        else:
            return jsonify({'status': 'error', 'message': result.get('message')}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Payment initialization failed: {str(e)}'}), 500

@app.route('/api/payment/verify/<reference>', methods=['GET'])
def verify_payment(reference):
    """Verify payment"""
    try:
        if not reference:
            return jsonify({'status': 'error', 'message': 'Reference required'}), 400
        
        # Check existing transaction
        existing_tx = db.get_transaction_by_reference(reference)
        if existing_tx and existing_tx.get('status') == 'success':
            return jsonify({
                'status': 'success',
                'message': 'Payment already verified',
                'data': existing_tx,
                'from_cache': True
            })
        
        # Verify with Paystack
        result = paystack.verify_transaction(reference)
        if result.get('status'):
            paystack_data = result['data']
            amount = paystack_data['amount'] / 100
            user_email = paystack_data.get('customer', {}).get('email', 'unknown')
            
            # Update transaction
            tx_update = {
                'status': 'success',
                'verified_at': datetime.now().isoformat(),
                'paystack_response': paystack_data,
                'amount_verified': amount
            }
            
            if existing_tx:
                db.update_transaction(existing_tx['id'], tx_update)
                tx_id = existing_tx['id']
            else:
                tx_data = {
                    'user_email': user_email,
                    'amount': amount,
                    'payment_reference': reference,
                    'status': 'success',
                    'type': 'wallet_funding',
                    'paystack_response': paystack_data,
                    'verified_at': datetime.now().isoformat()
                }
                tx_id = db.create_transaction(tx_data)
            
            # Credit user wallet
            if user_email and user_email != 'unknown':
                user = db.get_user_by_email(user_email)
                if user:
                    db.update_user_wallet(user['id'], amount)
                    
                    # Add profit for wallet funding (1.5%)
                    funding_profit = amount * 0.015
                    db.update_profit_wallet(funding_profit)
                    
                    print(f"💰 Credited ₦{amount} to {user_email}, Profit: ₦{funding_profit}")
            
            return jsonify({
                'status': 'success',
                'message': 'Payment verified',
                'data': {
                    **paystack_data,
                    'amount_in_naira': amount,
                    'transaction_id': tx_id
                }
            })
        else:
            return jsonify({'status': 'error', 'message': result.get('message')}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Verification failed: {str(e)}'}), 500

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/profit', methods=['GET'])
def get_profit_summary():
    """Get profit summary (admin only)"""
    try:
        user_email = request.args.get('user_email')
        
        if not user_email:
            return jsonify({'status': 'error', 'message': 'User email required'}), 401
        
        if not is_admin(user_email):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        return jsonify({
            'status': 'success',
            'data': db.profit_wallet
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/profit/withdraw', methods=['POST'])
def withdraw_profit():
    """Withdraw profit (admin only)"""
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
            return jsonify({'status': 'error', 'message': 'Minimum withdrawal: ₦1,000'}), 400
        
        if amount > 500000:
            return jsonify({'status': 'error', 'message': 'Maximum withdrawal: ₦500,000'}), 400
        
        if not bank_details or not all([
            bank_details.get('bank_name'),
            bank_details.get('account_number'),
            bank_details.get('account_name')
        ]):
            return jsonify({'status': 'error', 'message': 'Complete bank details required'}), 400
        
        # Check available balance
        available = db.profit_wallet['total_available']
        if amount > available:
            return jsonify({
                'status': 'error',
                'message': f'Insufficient balance. Available: ₦{available:,.2f}'
            }), 400
        
        # Process withdrawal
        success = db.update_profit_wallet(amount, "withdrawal")
        if not success:
            return jsonify({'status': 'error', 'message': 'Failed to update wallet'}), 400
        
        # Record withdrawal
        wd_data = {
            'user_email': user_email,
            'amount': amount,
            'bank_details': bank_details,
            'status': 'completed',
            'previous_balance': available,
            'new_balance': available - amount
        }
        wd_id = db.create_withdrawal(wd_data)
        
        print(f"💸 Profit withdrawal: ₦{amount} by {user_email}")
        
        return jsonify({
            'status': 'success',
            'message': 'Withdrawal completed',
            'data': {
                'withdrawal_id': wd_id,
                'amount': amount,
                'previous_balance': available,
                'new_balance': available - amount
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Withdrawal failed: {str(e)}'}), 500

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
    print(f"🔑 Paystack: {'✅ Configured' if paystack.secret_key else '❌ Not Configured'}")
    print(f"🔧 VTPass: {'✅ Configured' if vtpass.api_key else '❌ Not Configured'}")
    print(f"💰 Profitable Pricing: ✅ ENABLED")
    print(f"📊 Profit System: ✅ COMPLETE")
    print(f"💸 Withdrawal System: ✅ READY")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
