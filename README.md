# FraudShield

## 📌 Problem Statement: Fraud Shield for First-Time Digital Users

### Problem
First-time digital users are highly vulnerable to scams, phishing, and fraudulent transactions.

### Challenge
Develop a real-time system that:
- Warns users before risky transactions
- Detects suspicious activity patterns
- Educates users in simple, understandable language

### Goal
Increase trust in digital financial systems and protect new users from fraud.

---

## 🚀 Overview
**FraudShield** is a comprehensive, real-time protection platform designed specifically for new digital payment users. It actively monitors, flags, and prevents potentially fraudulent transactions before they happen. By combining an intuitive user interface, a fast rule-based risk analysis engine, and gamified user education, it ensures a safe and secure environment for modern digital transactions.

---

## 🛠️ Technical Specifications

### Tech Stack
- **Frontend**: Vanilla HTML5, CSS3, and JavaScript. Designed with a mobile-first, full-bleed professional UI approach.
- **Backend**: Python with **FastAPI** for high-performance, asynchronous REST API endpoints.
- **Database**: SQLite (`fraudshield.db`) for lightweight, reliable, and fast local data persistence.

### Key Features & Implementation Details

#### 1. Real-Time Risk Analysis Engine
The system performs instant background checks on transaction payloads via the `/api/analyze` endpoint.
- **UPI Risk Scoring**: Evaluates UPI handles, transaction amounts, and payment purposes.
  - Checks against a blocklist of known phishing keywords (e.g., "scam", "lottery", "refund", "customer-care").
  - Identifies suspicious top-level domains (TLDs like `.tk`, `.xyz`).
  - Flags excessively high transaction amounts based on predefined risk thresholds.
  - Employs Regex patterns to catch deceptive handles trying to mimic official entities (e.g., "bank.official").
- **URL Analysis**: The `/api/analyze-url` endpoint scans URLs to identify missing HTTPS, deceptive banking keywords (e.g., "sbi", "hdfc"), and unverified domains to prevent phishing attacks.

#### 2. User Dashboard & Gamification
- **Safety Score & XP**: Users earn Experience Points (XP) and increase their Safety Score by executing safe, verified transactions. Conversely, interacting with blocked or risky entities decreases the score.
- **Stats Monitoring**: The user dashboard displays real-time metrics, including "Money Saved", "Transactions Protected", and "Total Threats Scanned", fostering trust and transparency.

#### 3. Smart Alert System
- Generates immediate "Critical" or "Warning" alerts whenever risky transactions or suspicious activities are detected.
- Transactions yielding a risk score above `60` are automatically flagged or blocked, notifying the user immediately.

#### 4. Educational Hub (Learn Module)
- Includes dedicated pages (`learn.html`) to educate users in simple, understandable language about common digital fraud vectors.
- Gamified learning elements are integrated to build habits that increase user awareness and trust in digital financial systems.

#### 5. User Management & Data Privacy
- Secure authentication system with password hashing (SHA-256).
- Complete isolation of user data (multi-tenant architecture on SQLite), ensuring users only see their own transactions, alerts, and metrics.

---

## 💻 Running the Application

### 1. Start the Backend Server
Navigate to the `backend/` directory and run the FastAPI server:
```bash
cd backend
python app.py
```
*(The API will start at `http://127.0.0.1:5001` with Uvicorn)*

### 2. Launch the Frontend Application
Simply open `index.html` or `login.html` in your web browser. Alternatively, you can serve the project using a local server for a better experience:
```bash
# Using Python's built-in http server
python -m http.server 8000
```
Then visit `http://localhost:8000/login.html`.

---
*Built to make digital payments safe, simple, and secure for everyone.*
