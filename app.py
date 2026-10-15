import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

load_dotenv()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError("Set FLASK_SECRET_KEY to a random secret of at least 32 characters in .env")
csrf = CSRFProtect(app)

DB_PATH = os.environ.get("DATABASE_PATH", "ecosphere.sqlite3")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SERVICE_SID = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")

def utcnow():
    return datetime.now(timezone.utc)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE,
            google_sub TEXT UNIQUE,
            email TEXT,
            password_hash TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL
        )""")

init_db()

def json_error(message, status=400):
    return jsonify({"ok": False, "error": message}), status

def twilio_verify_client():
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID]):
        raise RuntimeError("SMS provider is not configured. Set Twilio Verify credentials in .env.")
    return Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/api/config")
def public_config():
    return jsonify({"google_client_id": GOOGLE_CLIENT_ID})

@app.post("/api/send-otp")
def send_otp():
    data = request.get_json(silent=True) or {}
    phone = re.sub(r"\s+", "", str(data.get("phone", "")))
    # Require E.164 format, e.g. +919876543210.
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return json_error("Enter a valid phone number including country code, e.g. +919876543210.")
    try:
        client = twilio_verify_client()
        result = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verifications.create(
            to=phone, channel="sms"
        )
    except Exception:
        app.logger.exception("OTP delivery failed")
        return json_error("Could not send OTP. Check your SMS provider configuration and try again.", 502)
    session["pending_phone"] = phone
    session["otp_verified"] = False
    return jsonify({"ok": True, "message": "Verification code sent by SMS."})

@app.post("/api/verify-otp")
def verify_otp():
    data = request.get_json(silent=True) or {}
    code = str(data.get("otp", "")).strip()
    phone = session.get("pending_phone")
    if not phone:
        return json_error("Request an OTP first.")
    if not re.fullmatch(r"\d{4,10}", code):
        return json_error("Enter the verification code from your SMS.")
    try:
        client = twilio_verify_client()
        result = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verification_checks.create(
            to=phone, code=code
        )
    except Exception:
        app.logger.exception("OTP verification failed")
        return json_error("Could not verify that code. Request a new code if it has expired.", 400)
    if result.status != "approved":
        return json_error("Incorrect or expired OTP.", 400)
    session["otp_verified"] = True
    return jsonify({"ok": True, "message": "Phone verified."})

@app.post("/api/signup")
def signup():
    if not session.get("otp_verified") or not session.get("pending_phone"):
        return json_error("Verify your phone number before creating an account.", 403)
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if len(password) < 8:
        return json_error("Password must contain at least 8 characters.")
    if len(password) > 256:
        return json_error("Password is too long.")
    phone = session["pending_phone"]
    try:
        with db() as con:
            con.execute(
                "INSERT INTO users(phone, password_hash, created_at) VALUES(?,?,?)",
                (phone, generate_password_hash(password), utcnow().isoformat())
            )
            row = con.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone()
    except sqlite3.IntegrityError:
        return json_error("An account with this phone number already exists. Sign in instead.", 409)
    session.clear()
    session["user_id"] = row["id"]
    session.permanent = True
    return jsonify({"ok": True, "message": "Account created and signed in."})

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    phone = re.sub(r"\s+", "", str(data.get("phone", "")))
    password = str(data.get("password", ""))
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        # Generic response prevents account enumeration.
        if not user:
            return json_error("Phone number or password is incorrect.", 401)
        now = utcnow()
        locked_until = datetime.fromisoformat(user["locked_until"]) if user["locked_until"] else None
        if locked_until and now < locked_until:
            mins = max(1, int((locked_until - now).total_seconds() // 60))
            return json_error(f"Too many failed attempts. Try again in about {mins} minute(s).", 429)
        if locked_until and now >= locked_until:
            con.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
            user = con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not user["password_hash"] or not check_password_hash(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            lock = (now + timedelta(hours=1)).isoformat() if attempts >= 5 else None
            con.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                        (attempts, lock, user["id"]))
            if lock:
                return json_error("Five failed attempts reached. Password login is locked for one hour.", 429)
            return json_error(f"Phone number or password is incorrect. Failed attempts: {attempts}/5.", 401)
        con.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    return jsonify({"ok": True, "message": "Signed in successfully."})

@app.post("/api/google")
def google_login():
    if not GOOGLE_CLIENT_ID:
        return json_error("Google sign-in is not configured on this server.", 503)
    data = request.get_json(silent=True) or {}
    credential = str(data.get("credential", ""))
    if not credential:
        return json_error("Google credential is missing.")
    try:
        claims = id_token.verify_oauth2_token(
            credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except Exception:
        return json_error("Google sign-in could not be verified. Please try again.", 401)
    sub = claims.get("sub")
    email = claims.get("email", "")
    email_verified = claims.get("email_verified") is True
    if not sub:
        return json_error("Google account could not be verified.", 401)
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE google_sub=?", (sub,)).fetchone()
        if not user and email and email_verified:
            # Link an existing account only when Google confirms the email is verified.
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user:
                con.execute("UPDATE users SET google_sub=? WHERE id=?", (sub, user["id"]))
        if not user:
            con.execute("INSERT INTO users(google_sub,email,created_at) VALUES(?,?,?)",
                        (sub, email if email_verified else None, utcnow().isoformat()))
            user = con.execute("SELECT * FROM users WHERE google_sub=?", (sub,)).fetchone()
        user_id = user["id"]
    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    return jsonify({"ok": True, "message": "Signed in with Google."})

@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": True, "authenticated": False})
    with db() as con:
        user = con.execute("SELECT id,phone,email FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return jsonify({"ok": True, "authenticated": False})
    return jsonify({"ok": True, "authenticated": True,
                    "user": {"phone": user["phone"], "email": user["email"]}})

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

if __name__ == "__main__":
    # Local development only. Use a production WSGI server and HTTPS when deployed.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
