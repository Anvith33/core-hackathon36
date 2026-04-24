import sqlite3

DB_NAME = "fraud.db"


# 🔌 Get database connection
def get_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print("DB Connection Error:", e)
        return None


# 🏗 Initialize database (MUST be called once at startup)
def init_db():
    conn = get_db()
    if not conn:
        return

    cur = conn.cursor()

    # Core transactions table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        amount REAL NOT NULL,
        risk TEXT,
        reason TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Optional users table (for demo enhancement)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE
    )
    """)

    conn.commit()
    conn.close()


# 💾 Save transaction safely
def save_transaction(sender, receiver, amount, risk=None, reasons=None):
    try:
        # 🚨 Basic validation (prevents crashes)
        if not sender or not receiver:
            print("Invalid transaction: sender/receiver missing")
            return False

        conn = get_db()
        cur = conn.cursor()

        # Default values for demo stability
        risk = risk if risk else "UNKNOWN"

        if isinstance(reasons, list):
            reason_text = ", ".join(reasons)
        elif reasons:
            reason_text = str(reasons)
        else:
            reason_text = "No reason provided"

        cur.execute("""
        INSERT INTO transactions (sender, receiver, amount, risk, reason)
        VALUES (?, ?, ?, ?, ?)
        """, (sender, receiver, amount, risk, reason_text))

        conn.commit()
        conn.close()

        # Debug (safe for hackathon)
        print(f"[DB] Saved: {sender} → {receiver} | ₹{amount} | {risk}")

        return True

    except Exception as e:
        print("Save Transaction Error:", e)
        return False


# 📜 Get all transactions (for demo/history)
def get_transactions():
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM transactions ORDER BY timestamp DESC")
        rows = cur.fetchall()

        conn.close()
        return [dict(row) for row in rows]

    except Exception as e:
        print("Fetch Transactions Error:", e)
        return []


# 🧠 Check if receiver is known
def is_known_receiver(sender, receiver):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        SELECT 1 FROM transactions
        WHERE sender = ? AND receiver = ?
        LIMIT 1
        """, (sender, receiver))

        result = cur.fetchone()
        conn.close()

        return result is not None

    except Exception as e:
        print("Known Receiver Error:", e)
        return False


# ✏️ Update risk after analysis (optional use)
def update_risk(transaction_id, risk, reason):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        UPDATE transactions
        SET risk = ?, reason = ?
        WHERE id = ?
        """, (risk, reason, transaction_id))

        conn.commit()
        conn.close()

        return True

    except Exception as e:
        print("Update Risk Error:", e)
        return False


# 👤 Create user (optional)
def create_user(name, email):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO users (name, email)
        VALUES (?, ?)
        """, (name, email))

        conn.commit()
        user_id = cur.lastrowid
        conn.close()

        return user_id

    except Exception as e:
        print("Create User Error:", e)
        return None


# 👤 Get user by ID
def get_user(user_id):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()

        conn.close()
        return dict(row) if row else None

    except Exception as e:
        print("Get User Error:", e)
        return None


# 📂 Get transactions for a specific sender
def get_user_transactions(sender):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        SELECT * FROM transactions
        WHERE sender = ?
        ORDER BY timestamp DESC
        """, (sender,))

        rows = cur.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    except Exception as e:
        print("User Transactions Error:", e)
        return []


# ⏱ Get last transaction (useful for pattern detection)
def get_last_transaction(sender):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        SELECT * FROM transactions
        WHERE sender = ?
        ORDER BY timestamp DESC
        LIMIT 1
        """, (sender,))

        row = cur.fetchone()
        conn.close()

        return dict(row) if row else None

    except Exception as e:
        print("Last Transaction Error:", e)
        return None