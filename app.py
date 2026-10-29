from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import mysql.connector
import hashlib
import hmac
import secrets
import time
import os
import re
from functools import wraps
from datetime import datetime, timedelta
import threading

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

# MySQL configuration
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', '3306'))
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'root')
DB_NAME = os.getenv('DB_NAME', 'banking_system')
TRANSFER_MIN = 1.0
TRANSFER_MAX = 50000.0
DAILY_LIMIT = 100000.0
SESSION_TIMEOUT = 900  # 15 minutes

# Rate limiting store
rate_limit_store = {}
rate_limit_lock = threading.Lock()

# ─── DATABASE SETUP ───────────────────────────────────────────────────────────

def get_db():
    return MySQLConnection()


class MySQLConnection:
    """Compatibility wrapper that keeps the existing conn.execute() style."""
    def __init__(self):
        self.conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER,
            password=DB_PASSWORD, database=DB_NAME
        )

    def execute(self, query, params=()):
        query = query.replace('?', '%s')
        cursor = self.conn.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def init_db():
    conn = get_db()
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            full_name VARCHAR(150) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            phone VARCHAR(20),
            account_type ENUM('Savings','Current') DEFAULT 'Savings',
            balance DECIMAL(15,2) DEFAULT 10000.00,
            account_number VARCHAR(50) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_attempts INT DEFAULT 0,
            locked_until DATETIME NULL,
            last_login DATETIME NULL
        ) ENGINE=InnoDB""",
        """CREATE TABLE IF NOT EXISTS transactions (
            id INT PRIMARY KEY AUTO_INCREMENT,
            from_account VARCHAR(50),
            to_account VARCHAR(50),
            amount DECIMAL(15,2) NOT NULL,
            type VARCHAR(50) NOT NULL,
            description VARCHAR(255),
            status VARCHAR(30) DEFAULT 'completed',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reference VARCHAR(50) UNIQUE NOT NULL,
            INDEX idx_tx_from (from_account),
            INDEX idx_tx_to (to_account),
            INDEX idx_tx_timestamp (timestamp)
        ) ENGINE=InnoDB""",
        """CREATE TABLE IF NOT EXISTS sessions (
            token VARCHAR(128) PRIMARY KEY,
            user_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            ip_address VARCHAR(45),
            CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB""",
        """CREATE TABLE IF NOT EXISTS audit_log (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NULL,
            action VARCHAR(100) NOT NULL,
            details TEXT,
            ip_address VARCHAR(45),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success TINYINT(1) DEFAULT 1,
            CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB"""
    ]
    for statement in statements:
        conn.execute(statement)

    demo_users = [
        ('alice', 'password123', 'Alice Johnson', 'alice@bank.com', 25000.00),
        ('bob', 'password123', 'Bob Smith', 'bob@bank.com', 15000.00),
        ('carol', 'password123', 'Carol White', 'carol@bank.com', 50000.00),
    ]
    for username, password, full_name, email, balance in demo_users:
        existing = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        if not existing:
            salt = secrets.token_hex(16)
            pw_hash = hash_password(password, salt)
            acc_num = generate_account_number()
            conn.execute(
                """INSERT INTO users (username, password_hash, salt, full_name, email, balance, account_number)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (username, pw_hash, salt, full_name, email, balance, acc_num)
            )
    conn.commit()
    conn.close()

# ─── SECURITY HELPERS ─────────────────────────────────────────────────────────

def hash_password(password: str, salt: str) -> str:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000)
    return key.hex()

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), stored_hash)

def generate_account_number() -> str:
    return 'ACC' + secrets.token_hex(5).upper()

def generate_reference() -> str:
    return 'TXN' + secrets.token_hex(8).upper()

def create_session(user_id: int, ip: str) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.utcnow() + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
    conn = get_db()
    conn.execute('INSERT INTO sessions (token, user_id, expires_at, ip_address) VALUES (?,?,?,?)',
                 (token, user_id, expires, ip))
    conn.commit()
    conn.close()
    return token

def get_session_user(token: str):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        'SELECT s.user_id, s.expires_at, u.username, u.full_name, u.account_number, u.balance, u.email '
        'FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=?', (token,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    expires_at = row['expires_at'] if isinstance(row['expires_at'], datetime) else datetime.fromisoformat(row['expires_at'])
    if datetime.utcnow() > expires_at:
        return None
    return dict(row)

def rate_limit(ip: str, action: str, max_req=10, window=60) -> bool:
    key = f"{ip}:{action}"
    now = time.time()
    with rate_limit_lock:
        if key not in rate_limit_store:
            rate_limit_store[key] = []
        rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window]
        if len(rate_limit_store[key]) >= max_req:
            return False
        rate_limit_store[key].append(now)
        return True

def audit(user_id, action, details, ip, success=True):
    conn = get_db()
    conn.execute('INSERT INTO audit_log (user_id, action, details, ip_address, success) VALUES (?,?,?,?,?)',
                 (user_id, action, details, ip, int(success)))
    conn.commit()
    conn.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Auth-Token') or request.cookies.get('auth_token')
        user = get_session_user(token)
        if not user:
            return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
        request.current_user = user
        request.auth_token = token
        return f(*args, **kwargs)
    return decorated

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if not rate_limit(ip, 'login', max_req=5, window=60):
        return jsonify({'error': 'Too many login attempts. Try again in 60 seconds.'}), 429

    data = request.json or {}
    username = str(data.get('username', '')).strip().lower()
    password = str(data.get('password', ''))

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

    if not user:
        audit(None, 'LOGIN_FAIL', f'Unknown user: {username}', ip, False)
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Check lock
    if user['locked_until']:
        locked_until = user['locked_until'] if isinstance(user['locked_until'], datetime) else datetime.fromisoformat(user['locked_until'])
        if datetime.utcnow() < locked_until:
            remaining = int((locked_until - datetime.utcnow()).total_seconds())
            conn.close()
            return jsonify({'error': f'Account locked. Try again in {remaining}s'}), 423

    if not verify_password(password, user['salt'], user['password_hash']):
        fails = user['failed_attempts'] + 1
        lock_until = None
        if fails >= 5:
            lock_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        conn.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?',
                     (fails, lock_until, user['id']))
        conn.commit()
        audit(user['id'], 'LOGIN_FAIL', 'Bad password', ip, False)
        conn.close()
        return jsonify({'error': 'Invalid credentials', 'attempts_remaining': max(0, 5 - fails)}), 401

    # Success
    conn.execute('UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?',
                 (datetime.utcnow().isoformat(), user['id']))
    conn.commit()
    token = create_session(user['id'], ip)
    audit(user['id'], 'LOGIN_SUCCESS', '', ip)
    conn.close()

    resp = jsonify({
        'success': True,
        'token': token,
        'user': {
            'username': user['username'],
            'full_name': user['full_name'],
            'account_number': user['account_number'],
            'email': user['email'],
            'balance': float(user['balance']),
        }
    })
    resp.set_cookie('auth_token', token, httponly=True, samesite='Strict', max_age=SESSION_TIMEOUT)
    return resp

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.auth_token
    conn = get_db()
    conn.execute('DELETE FROM sessions WHERE token=?', (token,))
    conn.commit()
    conn.close()
    audit(request.current_user['user_id'], 'LOGOUT', '', request.remote_addr)
    resp = jsonify({'success': True})
    resp.delete_cookie('auth_token')
    return resp

@app.route('/api/account/balance', methods=['GET'])
@require_auth
def get_balance():
    conn = get_db()
    user = conn.execute('SELECT balance, account_number, full_name FROM users WHERE id=?',
                        (request.current_user['user_id'],)).fetchone()
    conn.close()
    return jsonify({'balance': float(user['balance']), 'account_number': user['account_number'],
                    'full_name': user['full_name']})

@app.route('/api/account/transactions', methods=['GET'])
@require_auth
def get_transactions():
    acc = request.current_user['account_number']
    limit = min(int(request.args.get('limit', 20)), 100)
    conn = get_db()
    txns = conn.execute(
        '''SELECT * FROM transactions
           WHERE from_account=? OR to_account=?
           ORDER BY timestamp DESC LIMIT ?''',
        (acc, acc, limit)
    ).fetchall()
    conn.close()
    result = []
    for t in txns:
        d = dict(t)
        d['direction'] = 'debit' if d['from_account'] == acc else 'credit'
        result.append(d)
    return jsonify({'transactions': result})

@app.route('/api/transfer', methods=['POST'])
@require_auth
def transfer():
    ip = request.remote_addr
    user_id = request.current_user['user_id']

    if not rate_limit(ip, 'transfer', max_req=10, window=60):
        return jsonify({'error': 'Transfer rate limit exceeded'}), 429

    data = request.json or {}
    to_account = str(data.get('to_account', '')).strip().upper()
    try:
        amount = float(data.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    description = str(data.get('description', 'Transfer'))[:200]

    # Boundary checks
    if amount < TRANSFER_MIN:
        return jsonify({'error': f'Minimum transfer amount is ₹{TRANSFER_MIN:.2f}'}), 400
    if amount > TRANSFER_MAX:
        return jsonify({'error': f'Maximum single transfer is ₹{TRANSFER_MAX:,.2f}'}), 400

    conn = get_db()
    sender = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    from_account = sender['account_number']

    if to_account == from_account:
        conn.close()
        return jsonify({'error': 'Cannot transfer to own account'}), 400

    recipient = conn.execute('SELECT * FROM users WHERE account_number=?', (to_account,)).fetchone()
    if not recipient:
        conn.close()
        audit(user_id, 'TRANSFER_FAIL', f'Unknown account: {to_account}', ip, False)
        return jsonify({'error': 'Recipient account not found'}), 404

    # Daily limit check
    today = datetime.utcnow().date().isoformat()
    daily_total = conn.execute(
        '''SELECT COALESCE(SUM(amount),0) as total FROM transactions
           WHERE from_account=? AND date(timestamp)=? AND status='completed' ''',
        (from_account, today)
    ).fetchone()['total']

    if float(daily_total or 0) + amount > DAILY_LIMIT:
        conn.close()
        return jsonify({'error': f'Daily transfer limit of ₹{DAILY_LIMIT:,.2f} would be exceeded'}), 400

    if float(sender['balance']) < amount:
        conn.close()
        audit(user_id, 'TRANSFER_FAIL', 'Insufficient funds', ip, False)
        return jsonify({'error': 'Insufficient funds'}), 400

    ref = generate_reference()
    try:
        conn.execute('UPDATE users SET balance=balance-? WHERE id=?', (amount, user_id))
        conn.execute('UPDATE users SET balance=balance+? WHERE id=?', (amount, recipient['id']))
        conn.execute(
            '''INSERT INTO transactions (from_account, to_account, amount, type, description, reference)
               VALUES (?,?,?,?,?,?)''',
            (from_account, to_account, amount, 'transfer', description, ref)
        )
        conn.commit()
        new_balance = conn.execute('SELECT balance FROM users WHERE id=?', (user_id,)).fetchone()['balance']
        audit(user_id, 'TRANSFER_SUCCESS', f'₹{amount} to {to_account} ref={ref}', ip)
        conn.close()
        return jsonify({
            'success': True,
            'reference': ref,
            'amount': amount,
            'to_account': to_account,
            'recipient_name': recipient['full_name'],
            'new_balance': float(new_balance),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': 'Transaction failed. Please try again.'}), 500

@app.route('/api/account/lookup', methods=['GET'])
@require_auth
def lookup_account():
    acc = request.args.get('account_number', '').strip().upper()
    if not acc:
        return jsonify({'error': 'Account number required'}), 400
    conn = get_db()
    user = conn.execute('SELECT full_name, account_number FROM users WHERE account_number=?', (acc,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Account not found'}), 404
    return jsonify({'full_name': user['full_name'], 'account_number': user['account_number']})

@app.route('/api/test/stress', methods=['POST'])
@require_auth
def stress_test():
    """Simulate multiple rapid transactions for stress testing"""
    data = request.json or {}
    count = min(int(data.get('count', 10)), 50)
    results = {'success': 0, 'failed': 0, 'errors': [], 'duration_ms': 0}
    start = time.time()

    conn = get_db()
    for i in range(count):
        try:
            ref = generate_reference()
            conn.execute(
                '''INSERT INTO transactions (from_account, to_account, amount, type, description, reference, status)
                   VALUES (?,?,?,?,?,?,?)''',
                ('STRESS_TEST', 'STRESS_TEST', 0.01, 'stress_test', f'Stress #{i+1}', ref, 'test')
            )
            results['success'] += 1
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(str(e))
    conn.commit()
    conn.close()
    results['duration_ms'] = round((time.time() - start) * 1000, 2)
    results['tps'] = round(count / max((time.time() - start), 0.001), 1)
    return jsonify(results)

@app.route('/api/audit/log', methods=['GET'])
@require_auth
def get_audit_log():
    conn = get_db()
    logs = conn.execute(
        'SELECT * FROM audit_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 50',
        (request.current_user['user_id'],)
    ).fetchall()
    conn.close()
    return jsonify({'logs': [dict(l) for l in logs]})

@app.route('/api/accounts/list', methods=['GET'])
@require_auth
def list_accounts():
    """List other accounts for transfer lookup"""
    conn = get_db()
    accounts = conn.execute(
        'SELECT full_name, account_number FROM users WHERE id!=?',
        (request.current_user['user_id'],)
    ).fetchall()
    conn.close()
    return jsonify({'accounts': [dict(a) for a in accounts]})

if __name__ == '__main__':
    init_db()
    print("\n🏦 Banking System Started!")
    print("━" * 40)
    print("📍 URL: http://localhost:5000")
    print("👤 Demo accounts: alice / bob / carol")
    print("🔑 Password: password123")
    print("━" * 40 + "\n")
    app.run(debug=True, port=5000)
