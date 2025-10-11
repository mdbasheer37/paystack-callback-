
import os
import json
import hmac
import hashlib
import requests
import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import re

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configuration
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

# Firebase Client
class FirebaseClient:
    _instance = None
    
    def __init__(self):
        if not firebase_admin._apps:
            if os.getenv('FIREBASE_CREDENTIALS_JSON'):
                cred_json = json.loads(os.getenv('FIREBASE_CREDENTIALS_JSON'))
                cred = credentials.Certificate(cred_json)
            else:
                cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH')
                if cred_path:
                    cred = credentials.Certificate(cred_path)
                else:
                    raise ValueError("Firebase credentials not provided")
            
            firebase_admin.initialize_app(cred, {
                'databaseURL': os.getenv('FIREBASE_DB_URL')
            })
        
        self.root_ref = db.reference('/')
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def create_user(self, user_data: Dict[str, Any]) -> str:
        user_ref = self.root_ref.child('users').push(user_data)
        return user_ref.key
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        user_ref = self.root_ref.child(f'users/{user_id}')
        return user_ref.get()
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        users_ref = self.root_ref.child('users')
        users = users_ref.get()
        
        if users:
            for user_id, user_data in users.items():
                if user_data.get('email') == email:
                    return {**user_data, 'id': user_id}
        return None
    
    def update_user_wallet(self, user_id: str, amount: float) -> bool:
        try:
            user_ref = self.root_ref.child(f'users/{user_id}/wallet_balance')
            current_balance = user_ref.get() or 0
            user_ref.set(float(current_balance) + amount)
            return True
        except Exception:
            return False
    
    def create_transaction(self, transaction_data: Dict[str, Any]) -> str:
        transaction_ref = self.root_ref.child('transactions').push(transaction_data)
        return transaction_ref.key
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        transaction_ref = self.root_ref.child(f'transactions/{transaction_id}')
        return transaction_ref.get()
    
    def get_transaction_by_reference(self, reference: str) -> Optional[Dict[str, Any]]:
        transactions_ref = self.root_ref.child('transactions')
        transactions = transactions_ref.get()
        
        if transactions:
            for tx_id, tx_data in transactions.items():
                if tx_data.get('payment_reference') == reference:
                    return {**tx_data, 'id': tx_id}
        return None
    
    def update_profit_wallet(self, amount: float) -> bool:
        try:
            profit_ref = self.root_ref.child('profit_wallet/total_available')
            current_profit = profit_ref.get() or 0
            profit_ref.set(float(current_profit) + amount)
            return True
        except Exception:
            return False
    
    def create_profit_ledger_entry(self, ledger_data: Dict[str, Any]) -> str:
        ledger_ref = self.root_ref.child('profit_ledger').push(ledger_data)
        return ledger_ref.key
    
    def get_profit_ledger_entries(self, status: str = None) -> Dict[str, Any]:
        ledger_ref = self.root_ref.child('profit_ledger')
        entries = ledger_ref.get() or {}
        
        if status:
            return {k: v for k, v in entries.items() if v.get('status') == status}
        return entries
    
    def create_recipient(self, recipient_data: Dict[str, Any]) -> str:
        recipient_ref = self.root_ref.child('recipients').push(recipient_data)
        return recipient_ref.key
    
    def get_recipient(self, recipient_code: str) -> Optional[Dict[str, Any]]:
        recipients_ref = self.root_ref.child('recipients')
        recipients = recipients_ref.get()
        
        if recipients:
            for rec_id, rec_data in recipients.items():
                if rec_data.get('recipient_code') == recipient_code:
                    return {**rec_data, 'id': rec_id}
        return None

# Paystack Service
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
            'amount': amount * 100,  # Convert to kobo
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
            'amount': amount * 100,  # Convert to kobo
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

# VTPass Service
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
            return {'status': 'failed', 'message': str(e)}
    
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
            return {'status': 'failed', 'message': str(e)}
    
    def get_service_variations(self, service_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/service-variations"
        
        params = {'serviceID': service_id}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'status': 'failed', 'message': str(e)}

# Validation Utilities
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

# Flask App
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize Firebase
firebase_client = FirebaseClient.get_instance()

# Payment Routes
@app.route('/api/payment/initialize', methods=['POST'])
def initialize_payment():
    data = request.get_json()
    
    is_valid, error_msg = validate_payment_request(data)
    if not is_valid:
        return jsonify({'status': 'error', 'message': error_msg}), 400
    
    paystack = PaystackService()
    channel = data.get('channel', 'card')
    metadata = data.get('metadata', {})
    
    result = paystack.initialize_transaction(
        email=data['email'],
        amount=int(data['amount']),
        channel=channel,
        metadata=metadata
    )
    
    if result.get('status'):
        tx_data = {
            'user_email': data['email'],
            'amount': float(data['amount']),
            'channel': channel,
            'payment_reference': result['data']['reference'],
            'status': 'pending',
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

@app.route('/api/payment/virtual-account', methods=['POST'])
def create_virtual_account():
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
    
    paystack = PaystackService()
    amount = data.get('amount')
    
    result = paystack.create_dedicated_account(
        email=data['email'],
        amount=int(amount) if amount else None
    )
    
    if result.get('status'):
        account_data = result['data']
        
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

@app.route('/api/payment/verify/<reference>', methods=['GET'])
def verify_payment(reference):
    if not reference:
        return jsonify({'status': 'error', 'message': 'Reference is required'}), 400
    
    existing_tx = firebase_client.get_transaction_by_reference(reference)
    
    if existing_tx and existing_tx.get('status') == 'success':
        return jsonify({
            'status': 'success',
            'data': existing_tx,
            'from_cache': True
        })
    
    paystack = PaystackService()
    result = paystack.verify_transaction(reference)
    
    if result.get('status') and result['data']['status'] == 'success':
        tx_data = {
            'status': 'success',
            'verified_at': {'.sv': 'timestamp'},
            'paystack_response': result['data']
        }
        
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

@app.route('/api/payment/webhook/paystack', methods=['POST'])
def paystack_webhook():
    payload = request.get_data()
    signature = request.headers.get('x-paystack-signature')
    
    paystack = PaystackService()
    if not paystack.verify_webhook_signature(payload, signature):
        return jsonify({'status': 'error', 'message': 'Invalid signature'}), 400
    
    webhook_data = request.get_json()
    event = webhook_data.get('event')
    
    if event == 'charge.success':
        data = webhook_data.get('data', {})
        reference = data.get('reference')
        amount = data.get('amount', 0) / 100
        
        existing_tx = firebase_client.get_transaction_by_reference(reference)
        
        if existing_tx:
            tx_update = {
                'status': 'success',
                'webhook_processed_at': {'.sv': 'timestamp'},
                'paystack_webhook_data': webhook_data
            }
            
            if existing_tx.get('type') == 'wallet_funding':
                user_email = existing_tx.get('user_email')
                user = firebase_client.get_user_by_email(user_email)
                if user:
                    firebase_client.update_user_wallet(user['id'], amount)
    
    return jsonify({'status': 'success'})

# VTPass Routes
@app.route('/api/vtpass/pay', methods=['POST'])
def vtpass_pay():
    data = request.get_json()
    
    is_valid, error_msg = validate_vtpass_request(data)
    if not is_valid:
        return jsonify({'status': 'error', 'message': error_msg}), 400
    
    selling_price = float(data['amount'])
    vendor_price = data.get('vendor_price')
    profit_amount = data.get('profit')
    
    if profit_amount is None:
        if vendor_price is not None:
            profit_amount = selling_price - float(vendor_price)
        else:
            profit_amount = selling_price * 0.1
    
    if profit_amount < 0:
        return jsonify({'status': 'error', 'message': 'Invalid profit calculation'}), 400
    
    user_email = data.get('user_email')
    
    if user_email:
        user = firebase_client.get_user_by_email(user_email)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        if user.get('wallet_balance', 0) < selling_price:
            return jsonify({'status': 'error', 'message': 'Insufficient wallet balance'}), 400
        
        firebase_client.update_user_wallet(user['id'], -selling_price)
    
    vtpass = VTPassService()
    result = vtpass.pay(
        service_id=data['serviceID'],
        billers_code=data['billersCode'],
        variation_code=data['variation_code'],
        amount=selling_price,
        phone=data.get('phone'),
        request_id=data.get('request_id')
    )
    
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
    
    if result.get('code') == '000':
        firebase_client.update_profit_wallet(profit_amount)
        
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
        if user_email and user:
            firebase_client.update_user_wallet(user['id'], selling_price)
        
        return jsonify({
            'status': 'error',
            'message': result.get('response_description', 'VTPass payment failed'),
            'data': result
        }), 400

@app.route('/api/vtpass/verify', methods=['POST'])
def verify_service():
    data = request.get_json()
    
    if not data.get('serviceID') or not data.get('billersCode'):
        return jsonify({'status': 'error', 'message': 'serviceID and billersCode are required'}), 400
    
    vtpass = VTPassService()
    result = vtpass.verify_smartcard(
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

# Admin Routes
def require_admin_auth():
    admin_key = request.headers.get('X-Admin-API-Key') or request.json.get('admin_api_key')
    
    if not admin_key or admin_key != os.getenv('ADMIN_API_KEY'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    return None

@app.route('/api/admin/withdraw', methods=['POST'])
def admin_withdraw():
    auth_error = require_admin_auth()
    if auth_error:
        return auth_error
    
    data = request.get_json()
    
    if not data.get('recipient_account') and not data.get('recipient_bank_code'):
        return jsonify({'status': 'error', 'message': 'recipient_account or recipient_bank_code is required'}), 400
    
    if not data.get('amount'):
        return jsonify({'status': 'error', 'message': 'amount is required'}), 400
    
    valid, amount = validate_amount(data['amount'])
    if not valid:
        return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
    
    profit_wallet = firebase_client.root_ref.child('profit_wallet/total_available').get() or 0
    
    if amount > profit_wallet:
        return jsonify({'status': 'error', 'message': 'Insufficient profit balance'}), 400
    
    paystack = PaystackService()
    recipient_code = data.get('recipient_code')
    
    if not recipient_code:
        recipient_result = paystack.create_transfer_recipient(
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
        
        recipient_data = {
            'recipient_code': recipient_code,
            'bank_code': data['recipient_bank_code'],
            'account_number': data['recipient_account'],
            'account_name': recipient_result['data']['name'],
            'created_at': {'.sv': 'timestamp'}
        }
        
        firebase_client.create_recipient(recipient_data)
    
    transfer_result = paystack.initiate_transfer(
        recipient=recipient_code,
        amount=amount,
        reason=data.get('narration', 'Profit withdrawal')
    )
    
    if transfer_result.get('status'):
        firebase_client.update_profit_wallet(-amount)
        
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

# Health Check
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'service': 'VTU Backend API'})

@app.route('/')
def home():
    return jsonify({
        'message': 'VTU Backend API',
        'endpoints': {
            'payment': {
                'initialize': 'POST /api/payment/initialize',
                'virtual_account': 'POST /api/payment/virtual-account',
                'verify': 'GET /api/payment/verify/<reference>'
            },
            'vtpass': {
                'pay': 'POST /api/vtpass/pay',
                'verify': 'POST /api/vtpass/verify'
            },
            'admin': {
                'withdraw': 'POST /api/admin/withdraw'
            }
        }
    })

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
