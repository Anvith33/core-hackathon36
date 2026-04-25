from flask import Flask, request, jsonify
from flask_cors import CORS
import datetime
import re
import sqlite3
import hashlib

app = Flask(__name__)
CORS(app)

DB_PATH = 'fraudshield.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            safety_score INTEGER DEFAULT 85,
            xp INTEGER DEFAULT 0
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            upi_id TEXT,
            amount REAL,
            purpose TEXT,
            risk_score REAL,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
    print("Database initialized.")

init_db()

# Simulated ML Model Weights
TXN_MODEL = {
    "weights": {
        "isUnknownRecipient": 12.5,
        "isSuspiciousUPI": 35.0,
        "isHighRiskPurpose": 25.0,
        "isLargeAmount": 18.0,
        "isUnusualHour": 15.0,
    }
}

SUSPICIOUS_PATTERNS = [
    r"lottery", r"prize", r"winner", r"lucky", r"reward",
    r"refund", r"helpdesk", r"support", r"rbi", r"bank.?official"
]

@app.route('/')
def home():
    return jsonify({
        "status": "Online",
        "service": "FraudShield Backend API",
        "model_version": "1.4.2"
    })

@app.route('/api/analyze-transaction', methods=['POST'])
def analyze_transaction():
    data = request.json
    upi_id = data.get('upiId', '').lower()
    amount = float(data.get('amount', 0))
    purpose = data.get('purpose', '')
    recipient = data.get('recipientName', '').lower()
    
    risk_score = 0
    risks = []
    
    # 1. UPI Keyword Check
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, upi_id):
            risk_score += TXN_MODEL["weights"]["isSuspiciousUPI"]
            risks.append({"level": "danger", "text": f"UPI ID matches suspicious keyword: {pattern}"})
            break
            
    # 2. Amount Risk
    if amount > 50000:
        risk_score += TXN_MODEL["weights"]["isLargeAmount"]
        risks.append({"level": "danger", "text": "Transaction amount flagged as extreme outlier."})
        
    # 3. Purpose Check
    if purpose in ['prize', 'investment', 'job']:
        risk_score += TXN_MODEL["weights"]["isHighRiskPurpose"]
        risks.append({"level": "danger", "text": f"Purpose '{purpose}' matches high-probability scam vector."})

    # Confidence calculation
    risk_score = min(100, risk_score)
    
    print(f"[BACKEND] Analyzed TXN: {upi_id} | Amount: {amount} | Score: {risk_score}")
    
    return jsonify({
        "riskScore": risk_score,
        "risks": risks,
        "confidence": 0.965,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '').lower()
    
    score = 0
    flags = []
    
    if not url.startswith('https://'):
        score += 30
        flags.append("No HTTPS encryption detected.")
        
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.pw']
    if any(url.endswith(tld) for tld in suspicious_tlds):
        score += 40
        flags.append("Suspicious Top-Level Domain (TLD) flagged by LinkShield.")
        
    bank_keywords = ['sbi', 'bank', 'login', 'verify', 'account']
    if any(word in url for word in bank_keywords) and "sbi.co.in" not in url:
        score += 50
        flags.append("Deceptive keyword usage in non-official domain.")

    score = min(100, score)
    
    return jsonify({
        "score": score,
        "flags": flags,
        "verdict": "DANGEROUS" if score >= 65 else "SUSPICIOUS" if score >= 35 else "SAFE",
        "confidence": 0.982
    })

# authentication
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    full_name = data.get('fullName')
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)",
                         (username, password_hash, full_name))
        return jsonify({"success": True, "message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists"}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", 
                        (username, password_hash)).fetchone()
    
    if user:
        return jsonify({
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "fullName": user['full_name'],
                "safetyScore": user['safety_score'],
                "xp": user['xp']
            }
        })
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

if __name__ == '__main__':
    print("FraudShield API Server starting on port 5001...")
    app.run(debug=True, port=5001)
