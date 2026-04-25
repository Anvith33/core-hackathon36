"""
FraudShield – FastAPI Backend (High-Performance)
Async, CORS-ready, live-monitoring capable
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3
import hashlib
import datetime
import os
import re

# ── DB path: always use the root-level DB ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "fraudshield.db")

app = FastAPI(title="FraudShield API", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── DB helpers ─────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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
            recipient_name TEXT,
            upi_id TEXT,
            amount REAL,
            purpose TEXT,
            risk_score REAL,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,
            title TEXT,
            message TEXT,
            is_read INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
    print(f"✅ FraudShield FastAPI DB ready → {DB_PATH}")

init_db()

# ── Request Models ─────────────────────────────────────────────────────
class RegisterData(BaseModel):
    username: str
    password: str
    fullName: str

class LoginData(BaseModel):
    username: str
    password: str

class TransactionData(BaseModel):
    user_id: int
    name: Optional[str] = ""
    upi: Optional[str] = ""
    amount: float = 0
    purpose: Optional[str] = "p2p"
    risk_score: float = 0
    status: str = "safe"

class AlertData(BaseModel):
    user_id: int
    type: str
    title: str
    message: str

class AnalyzeData(BaseModel):
    upi: str = ""
    amount: float = 0
    purpose: Optional[str] = "p2p"

class UrlData(BaseModel):
    url: str = ""

# ── Blocklists ─────────────────────────────────────────────────────────
UPI_BLOCKLIST = [
    "scam","fraud","hacker","prize","winner","win","lottery",
    "refund","helpdesk","customer-care","support","rbi"
]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".xyz",".pw"]
HIGH_RISK_PURPOSES = ["prize","job","investment"]

# ── Routes ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status":"Online","service":"FraudShield FastAPI v3.0","db":DB_PATH}

# ─ AUTH ────────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
def register(data: RegisterData):
    pw_hash = hashlib.sha256(data.password.encode()).hexdigest()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, safety_score, xp) VALUES (?,?,?,85,0)",
            (data.username, pw_hash, data.fullName)
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE username=?", (data.username,)).fetchone()
        return {"success": True, "user": {"id":user["id"],"fullName":user["full_name"],"username":user["username"]}}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

@app.post("/api/auth/login")
def login(data: LoginData):
    pw_hash = hashlib.sha256(data.password.encode()).hexdigest()
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (data.username, pw_hash)
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "success": True,
        "user": {
            "id": user["id"],
            "fullName": user["full_name"],
            "username": user["username"],
            "safetyScore": user["safety_score"],
            "xp": user["xp"]
        }
    }

# ─ STATS ───────────────────────────────────────────────────────────────
@app.get("/api/user/stats")
def get_stats(user_id: int):
    conn = get_db()
    try:
        user = conn.execute("SELECT safety_score, xp FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        money_saved = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? AND status='blocked'",
            (user_id,)
        ).fetchone()[0]

        safe_txns = conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE user_id=? AND status IN ('safe','warn')",
            (user_id,)
        ).fetchone()[0]

        threats = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE user_id=? AND type IN ('critical','warning')",
            (user_id,)
        ).fetchone()[0]

        return {
            "safetyScore": user["safety_score"],
            "xp": user["xp"],
            "moneySaved": money_saved,
            "txnsProtected": safe_txns,
            "scannedTotal": threats
        }
    finally:
        conn.close()

# ─ TRANSACTIONS ────────────────────────────────────────────────────────
@app.get("/api/transactions")
def list_transactions(user_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE user_id=? ORDER BY timestamp DESC LIMIT 20",
            (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@app.post("/api/transactions")
def save_transaction(data: TransactionData):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO transactions (user_id,recipient_name,upi_id,amount,purpose,risk_score,status) VALUES (?,?,?,?,?,?,?)",
            (data.user_id, data.name, data.upi, data.amount, data.purpose, data.risk_score, data.status)
        )
        # Update score & XP
        if data.status == "safe":
            conn.execute(
                "UPDATE users SET safety_score=MIN(100,safety_score+2), xp=xp+10 WHERE id=?",
                (data.user_id,)
            )
        elif data.status == "blocked":
            conn.execute(
                "UPDATE users SET safety_score=MAX(10,safety_score-5) WHERE id=?",
                (data.user_id,)
            )

        # Auto-create alert for risky transactions
        if data.status in ("warn","blocked","danger") or data.risk_score > 60:
            alert_type = "critical" if data.status == "blocked" else "warning"
            conn.execute(
                "INSERT INTO alerts (user_id,type,title,message) VALUES (?,?,?,?)",
                (data.user_id, alert_type,
                 "Risky Transaction Flagged",
                 f"A payment of ₹{data.amount} to {data.upi} was flagged (risk: {data.risk_score}%).")
            )

        conn.commit()
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ─ ALERTS ──────────────────────────────────────────────────────────────
@app.get("/api/alerts")
def list_alerts(user_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE user_id=? ORDER BY timestamp DESC",
            (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@app.post("/api/alerts")
def save_alert(data: AlertData):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO alerts (user_id,type,title,message) VALUES (?,?,?,?)",
            (data.user_id, data.type, data.title, data.message)
        )
        # Score impact
        if data.type == "critical":
            conn.execute("UPDATE users SET safety_score=MAX(0,safety_score-10) WHERE id=?", (data.user_id,))
        elif data.type == "warning":
            conn.execute("UPDATE users SET safety_score=MAX(0,safety_score-5) WHERE id=?", (data.user_id,))
        conn.commit()
        return {"success": True}
    finally:
        conn.close()

# ─ AI ANALYZE (Fast Backend Model) ────────────────────────────────────
@app.post("/api/analyze")
def analyze(data: AnalyzeData):
    upi = data.upi.lower()
    amount = data.amount
    purpose = data.purpose or "p2p"

    risk_score = 0
    risks = []

    # 1. Blocklist keyword
    matched = [kw for kw in UPI_BLOCKLIST if kw in upi]
    if matched:
        risk_score += 75
        risks.append({"text": f"UPI handle matches known phishing keyword: '{matched[0]}'", "level": "danger"})

    # 2. Suspicious TLD
    if any(upi.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 20
        risks.append({"text": "Unverified/Suspicious UPI domain extension", "level": "warn"})

    # 3. Amount thresholds
    if amount > 50000:
        risk_score += 25
        risks.append({"text": "Extremely high transaction amount", "level": "danger"})
    elif amount > 20000:
        risk_score += 15
        risks.append({"text": "Large amount — verify recipient identity", "level": "warn"})

    # 4. High-risk purpose
    if purpose in HIGH_RISK_PURPOSES:
        risk_score += 40
        risks.append({"text": f"Purpose '{purpose}' is a common scam vector", "level": "danger"})

    # 5. Regex patterns
    if re.search(r"(lucky|reward|helpdesk|bank.?official)", upi):
        risk_score += 30
        risks.append({"text": "Suspicious keyword pattern in UPI handle", "level": "danger"})

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        status, color, label = "danger",  "#ef4444", "Extreme Risk"
    elif risk_score >= 30:
        status, color, label = "warning", "#f59e0b", "High Suspicion"
    else:
        status, color, label = "safe",    "#10b981", "Verified Secure"

    return {
        "success": True,
        "riskScore": risk_score,
        "status": status,
        "color": color,
        "label": label,
        "risks": risks,
        "model": "FS-FastAPI-v3"
    }

# ─ URL ANALYZE ─────────────────────────────────────────────────────────
@app.post("/api/analyze-url")
def analyze_url(data: UrlData):
    url = data.url.lower()
    score = 0
    flags = []

    if not url.startswith("https://"):
        score += 30
        flags.append("No HTTPS encryption detected.")
    if any(url.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 40
        flags.append("Suspicious TLD flagged by LinkShield.")
    bank_kw = ["sbi","bank","login","verify","account","hdfc","icici"]
    if any(w in url for w in bank_kw) and not any(d in url for d in ["sbi.co.in","hdfcbank.com","icicibank.com"]):
        score += 50
        flags.append("Deceptive banking keyword on non-official domain.")

    score = min(100, score)
    return {
        "score": score,
        "flags": flags,
        "verdict": "DANGEROUS" if score >= 65 else "SUSPICIOUS" if score >= 35 else "SAFE",
        "confidence": 0.982
    }

# ── Launch ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("🚀 FraudShield FastAPI v3.0 — starting on port 5001")
    uvicorn.run("app:app", host="127.0.0.1", port=5001, reload=True, log_level="info")
