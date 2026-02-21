# app.py
# Account Management Microservice (REST API + JSON) using SQLite (no subscription needed)
#
# Endpoints:
#   POST  /register
#   POST  /login
#   GET   /profile        (requires Authorization: Bearer <token>)
#   PATCH /profile        (requires Authorization: Bearer <token>)
#   GET   /health
#
# Response format:
#   Success: { "status": "ok", "data": { ... } }
#   Error:   { "status": "error", "error": { "code": "...", "message": "..." } }

import os
import re
import sqlite3
import datetime
from functools import wraps

from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)

# Secrets / config
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_change_me")
DB_PATH = os.environ.get("DATABASE_PATH", "users.db")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")  # YYYY-MM-DD


# Helpers: JSON responses

def json_ok(data, http_status=200):
    return jsonify({"status": "ok", "data": data}), http_status


def json_error(code, message, http_status):
    return jsonify({"status": "error", "error": {"code": code, "message": message}}), http_status


# -------------------------
# SQLite connection helpers
# -------------------------
def get_db() -> sqlite3.Connection:
    """Get a per-request DB connection."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                dob TEXT NOT NULL,
                address TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# -------------------------
# Auth helpers
# -------------------------
def get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def get_user_by_email(email: str):
    db = get_db()
    row = db.execute(
        "SELECT email, password_hash, full_name, dob, address FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    return row


def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return json_error("UNAUTHORIZED", "Authentication required.", 401)

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            email = (payload.get("email") or "").strip().lower()
            if not email:
                return json_error("INVALID_TOKEN", "Invalid token.", 401)

            user = get_user_by_email(email)
            if user is None:
                return json_error("UNAUTHORIZED", "Invalid token user.", 401)

        except jwt.ExpiredSignatureError:
            return json_error("TOKEN_EXPIRED", "Token expired.", 401)
        except jwt.InvalidTokenError:
            return json_error("INVALID_TOKEN", "Invalid token.", 401)

        # Pass sqlite row to the endpoint
        return fn(user, *args, **kwargs)

    return wrapper


# -------------------------
# Routes
# -------------------------
@app.get("/health")
def health():
    return json_ok({"message": "Service is running"})


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    full_name = (data.get("fullName") or "").strip()
    dob = (data.get("dob") or "").strip()
    address = (data.get("address") or "").strip()

    # User-visible meaning of "valid email"
    if not EMAIL_REGEX.match(email):
        return json_error(
            "INVALID_EMAIL_FORMAT",
            "Enter a valid email (example: name@email.com).",
            400,
        )

    if len(password) < 8:
        return json_error("WEAK_PASSWORD", "Password must be at least 8 characters long.", 400)

    if not full_name:
        return json_error("INVALID_FULLNAME", "Full name is required.", 400)

    if not DATE_REGEX.match(dob):
        return json_error("INVALID_DOB", "Date of birth must be in YYYY-MM-DD format.", 400)

    if not address:
        return json_error("INVALID_ADDRESS", "Address is required.", 400)

    db = get_db()

    # Check if email exists
    existing = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return json_error("EMAIL_EXISTS", "This email is already registered.", 409)

    password_hash = generate_password_hash(password)
    created_at = datetime.datetime.utcnow().isoformat()

    db.execute(
        """
        INSERT INTO users (email, password_hash, full_name, dob, address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (email, password_hash, full_name, dob, address, created_at),
    )
    db.commit()

    return json_ok({"message": "Account successfully created.", "email": email}, 201)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = get_user_by_email(email)
    if user is None:
        return json_error("USER_NOT_FOUND", "Account not found.", 404)

    if not check_password_hash(user["password_hash"], password):
        return json_error("INVALID_CREDENTIALS", "Incorrect email or password.", 401)

    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    token = jwt.encode({"email": email, "exp": exp}, app.config["SECRET_KEY"], algorithm="HS256")

    return json_ok({"token": token})


@app.get("/profile")
@token_required
def view_profile(current_user):
    return json_ok(
        {
            "email": current_user["email"],
            "fullName": current_user["full_name"],
            "dob": current_user["dob"],
            "address": current_user["address"],
        }
    )


@app.patch("/profile")
@token_required
def update_profile(current_user):
    data = request.get_json(silent=True) or {}

    # Only update fields provided
    allowed = {"fullName", "dob", "address", "email"}
    provided = {k: v for k, v in data.items() if k in allowed}

    if not provided:
        return json_ok({"message": "No changes detected."})

    db = get_db()
    old_email = current_user["email"]
    new_email = old_email  # may change

    # Validate and apply email update (optional)
    if "email" in provided:
        candidate = (provided["email"] or "").strip().lower()
        if not EMAIL_REGEX.match(candidate):
            return json_error(
                "INVALID_EMAIL_FORMAT",
                "Enter a valid email (example: name@email.com).",
                400,
            )

        if candidate != old_email:
            exists = db.execute("SELECT 1 FROM users WHERE email = ?", (candidate,)).fetchone()
            if exists:
                return json_error("EMAIL_EXISTS", "This email is already in use.", 409)
            new_email = candidate

    # Validate other fields (if present)
    if "fullName" in provided:
        name = (provided["fullName"] or "").strip()
        if not name:
            return json_error("INVALID_FULLNAME", "Full name cannot be empty.", 400)

    if "dob" in provided:
        candidate_dob = (provided["dob"] or "").strip()
        if not DATE_REGEX.match(candidate_dob):
            return json_error("INVALID_DOB", "Date of birth must be in YYYY-MM-DD format.", 400)

    if "address" in provided:
        addr = (provided["address"] or "").strip()
        if not addr:
            return json_error("INVALID_ADDRESS", "Address cannot be empty.", 400)

    # Build dynamic UPDATE
    set_clauses = []
    params = []

    if "fullName" in provided:
        set_clauses.append("full_name = ?")
        params.append((provided["fullName"] or "").strip())

    if "dob" in provided:
        set_clauses.append("dob = ?")
        params.append((provided["dob"] or "").strip())

    if "address" in provided:
        set_clauses.append("address = ?")
        params.append((provided["address"] or "").strip())

    # If email is changing, update the primary key
    if new_email != old_email:
        set_clauses.append("email = ?")
        params.append(new_email)

    # If only email changed, we still have clauses; if none, no changes
    if not set_clauses:
        return json_ok({"message": "No changes detected."})

    params.append(old_email)

    db.execute(
        f"UPDATE users SET {', '.join(set_clauses)} WHERE email = ?",
        tuple(params),
    )
    db.commit()

    return json_ok({"message": "Profile successfully updated.", "email": new_email})


# -------------------------
# Start
# -------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)