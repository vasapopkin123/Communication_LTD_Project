import os
import re
import time
import hashlib
import secrets
from datetime import datetime, timedelta, timezone 
import mysql.connector
from fastapi import FastAPI, HTTPException, Header , Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import hash_password_hmac, verify_password_hmac, validate_password_strength
from config import PASSWORD_CONFIG

# -----------------------------
# Security / Policy
# -----------------------------
LOCK_MINUTES = 30
AUTH_TOKEN_TTL_HOURS = 12
RESET_TOKEN_TTL_MINUTES = 30


# -----------------------------
# Whitelists
# -----------------------------
# Whitelist validation for names (prevents storing "<script...>" etc.)
NAME_RE = re.compile(r"^[A-Za-zא-ת][A-Za-zא-ת \-']{0,79}$")

USERNAME_RE = re.compile(r"^[A-Za-z0-9א-ת][A-Za-z0-9א-ת_.-]{2,31}$")

# Email: בדיקה בסיסית/פרקטית (לא RFC מלא), אורך סביר, בלי רווחים
EMAIL_RE = re.compile(r"^(?=.{5,254}$)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def utcnow_naive() -> datetime:
    # store as naive UTC for MySQL DATETIME
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def validate_person_name(value: str, field: str) -> None:
    if not value or not NAME_RE.match(value):
        raise HTTPException(status_code=400, detail=f"{field} contains invalid characters")

def validate_username(value: str) -> str:
    v = (value or "").strip()
    if not USERNAME_RE.match(v):
        raise HTTPException(
            status_code=400,
            detail="Username לא תקין: מותר אותיות/מספרים/._- (וללא רווחים), אורך 3–32",
        )
    return v

def validate_email(value: str) -> str:
    v = (value or "").strip()
    if not EMAIL_RE.match(v):
        raise HTTPException(status_code=400, detail="Email לא תקין")
    return v

# -----------------------------
# FastAPI + CORS
# -----------------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# DB
# -----------------------------
def get_db_connection():
    while True:
        try:
            return mysql.connector.connect(
                host="mysql",
                user="user",
                password="password",
                database="my_app_db",
            )
        except Exception:
            print("Database not ready, retrying in 2 seconds...")
            time.sleep(2)


def _try(cursor, sql: str):
    try:
        cursor.execute(sql)
    except mysql.connector.Error:
        pass


def ensure_schema():
    conn = get_db_connection()
    cur = conn.cursor()

    # Base tables
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            failed_attempts INT DEFAULT 0,
            is_locked BOOLEAN DEFAULT FALSE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            registered_by VARCHAR(255) NOT NULL
        )
        """
    )

    # Migrations / add columns (safe if already exists)
    _try(cur, "ALTER TABLE users ADD COLUMN locked_until DATETIME NULL")
    _try(cur, "ALTER TABLE password_history ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")

    _try(cur, "ALTER TABLE customers ADD COLUMN last_name VARCHAR(255) NULL")
    _try(cur, "ALTER TABLE customers ADD COLUMN registered_by_user_id INT NULL")
    _try(cur, "ALTER TABLE customers ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")

    # Auth tokens (session)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            revoked BOOLEAN DEFAULT FALSE,
            UNIQUE KEY uniq_token_hash (token_hash),
            INDEX idx_user (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    # Password reset tokens
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            INDEX idx_token_hash (token_hash),
            INDEX idx_user_expires (user_id, expires_at),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


ensure_schema()


# -----------------------------
# Models
# -----------------------------
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class CustomerCreateRequest(BaseModel):
    first_name: str
    last_name: str


class ForgotPasswordRequest(BaseModel):
    username: str
    email: str


class ResetPasswordRequest(BaseModel):
    username: str
    token: str
    new_password: str


# -----------------------------
# Auth helpers
# -----------------------------
def issue_auth_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)  # raw token shown to client once
    token_hash = sha256_hex(token)
    now = utcnow_naive()
    expires = now + timedelta(hours=AUTH_TOKEN_TTL_HOURS)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO auth_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
        (user_id, token_hash, expires),
    )
    conn.commit()
    conn.close()
    return token


def revoke_all_tokens(user_id: int) -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE auth_tokens SET revoked = 1 WHERE user_id = %s", (user_id,))
    conn.commit()
    conn.close()


def get_current_user(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        raise HTTPException(status_code=401, detail="Missing token")

    token_hash = sha256_hex(raw)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT u.id, u.username, u.email, t.expires_at, t.revoked
        FROM auth_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = %s
        LIMIT 1
        """,
        (token_hash,),
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid token")

    if row["revoked"]:
        conn.close()
        raise HTTPException(status_code=401, detail="Token revoked")

    if row["expires_at"] <= utcnow_naive():
        # auto revoke expired
        cur2 = conn.cursor()
        cur2.execute("UPDATE auth_tokens SET revoked = 1 WHERE token_hash = %s", (token_hash,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Token expired")

    conn.close()
    return {"id": row["id"], "username": row["username"], "email": row["email"]}


# -----------------------------
# Email (best-effort)
# -----------------------------
def send_email_best_effort(to_email: str, subject: str, body: str) -> bool:
    """
    Uses SMTP_* env vars if present; otherwise prints to console (demo-friendly).
    """
    from email.mime.text import MIMEText
    import smtplib

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")
    from_addr = os.getenv("SMTP_FROM") or user

    if not host or not user or not pwd or not from_addr:
        print("SMTP not configured. Email fallback to console.")
        print("To:", to_email)
        print("Subject:", subject)
        print(body)
        return False

    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email

    with smtplib.SMTP(host, port) as s:
        s.starttls()
        s.login(user, pwd)
        s.sendmail(from_addr, [to_email], msg.as_string())
    return True


# -----------------------------
# Endpoints
# -----------------------------
@app.post("/register")
def register(req: RegisterRequest):
    req.username = validate_username(req.username)
    req.email = validate_email(req.email)

    is_strong, msg = validate_password_strength(req.password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    pwd_hash, salt = hash_password_hmac(req.password)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)",
            (req.username, req.email, pwd_hash, salt),
        )
        user_id = cur.lastrowid
        cur.execute(
            "INSERT INTO password_history (user_id, password_hash, salt) VALUES (%s, %s, %s)",
            (user_id, pwd_hash, salt),
        )
        conn.commit()
    except Exception:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

    return {"message": "Success"}


@app.post("/login")
def login(req: LoginRequest):
    req.username = validate_username(req.username)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username = %s", (req.username,))
    db_user = cur.fetchone()

    if not db_user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    now = utcnow_naive()

    # Legacy unlock once: old DB had is_locked=1 with no locked_until
    if db_user.get("is_locked") and db_user.get("locked_until") is None:
        cur2 = conn.cursor()
        cur2.execute("UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = %s", (db_user["id"],))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (db_user["id"],))
        db_user = cur.fetchone()

    locked_until = db_user.get("locked_until")

    # Time-based lock
    if locked_until and locked_until > now:
        remaining = int((locked_until - now).total_seconds() // 60) + 1
        conn.close()
        raise HTTPException(status_code=403, detail=f"החשבון נעול לעוד {remaining} דקות")

    # Auto-unlock if time passed
    if locked_until and locked_until <= now:
        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = %s",
            (db_user["id"],),
        )
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (db_user["id"],))
        db_user = cur.fetchone()

    # Verify password
    if verify_password_hmac(req.password, db_user["password_hash"], db_user["salt"]):
        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE id = %s",
            (db_user["id"],),
        )
        conn.commit()
        conn.close()

        token = issue_auth_token(db_user["id"])
        return {"message": "Success", "token": token, "username": db_user["username"]}

    # Wrong password: increment + lock for 30 minutes after max attempts
    new_attempts = int(db_user.get("failed_attempts") or 0) + 1
    lock_now = new_attempts >= PASSWORD_CONFIG["max_login_attempts"]

    cur2 = conn.cursor()
    if lock_now:
        until = now + timedelta(minutes=LOCK_MINUTES)
        cur2.execute(
            "UPDATE users SET failed_attempts = %s, is_locked = 1, locked_until = %s WHERE id = %s",
            (new_attempts, until, db_user["id"]),
        )
    else:
        cur2.execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (new_attempts, db_user["id"]))

    conn.commit()
    conn.close()

    if lock_now:
        raise HTTPException(status_code=401, detail="החשבון ננעל ל-30 דקות עקב 3 ניסיונות כושלים")
    raise HTTPException(status_code=401, detail="סיסמה שגויה")


@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    return {"id": u["id"], "username": u["username"], "email": u["email"]}


@app.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"message": "Logged out"}

    raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        return {"message": "Logged out"}

    token_hash = sha256_hex(raw)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE auth_tokens SET revoked = 1 WHERE token_hash = %s", (token_hash,))
    conn.commit()
    conn.close()

    return {"message": "Logged out"}


@app.post("/change-password")
def change_password(req: ChangePasswordRequest, authorization: str | None = Header(default=None)):
    current = get_current_user(authorization)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (current["id"],))
    user = cur.fetchone()

    if not user or not verify_password_hmac(req.old_password, user["password_hash"], user["salt"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Old password incorrect")

    # history check (last N)
    cur.execute(
        "SELECT password_hash, salt FROM password_history WHERE user_id = %s ORDER BY id DESC LIMIT %s",
        (user["id"], PASSWORD_CONFIG["history_limit"]),
    )
    history = cur.fetchall()
    for entry in history:
        if verify_password_hmac(req.new_password, entry["password_hash"], entry["salt"]):
            conn.close()
            raise HTTPException(status_code=400, detail="לא ניתן להשתמש בסיסמה שהייתה בשימוש לאחרונה")

    is_strong, msg = validate_password_strength(req.new_password)
    if not is_strong:
        conn.close()
        raise HTTPException(status_code=400, detail=msg)

    new_hash, new_salt = hash_password_hmac(req.new_password)

    cur2 = conn.cursor()
    cur2.execute(
        "UPDATE users SET password_hash = %s, salt = %s WHERE id = %s",
        (new_hash, new_salt, user["id"]),
    )
    cur2.execute(
        "INSERT INTO password_history (user_id, password_hash, salt) VALUES (%s, %s, %s)",
        (user["id"], new_hash, new_salt),
    )
    conn.commit()
    conn.close()

    # Security: revoke all sessions after password change
    revoke_all_tokens(user["id"])

    return {"message": "Updated"}


@app.post("/add-customer")
def add_customer(req: CustomerCreateRequest, authorization: str | None = Header(default=None)):
    current = get_current_user(authorization)

    validate_person_name(req.first_name, "first_name")
    validate_person_name(req.last_name, "last_name")

    full_name = f"{req.first_name} {req.last_name}"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO customers (full_name, last_name, registered_by, registered_by_user_id)
        VALUES (%s, %s, %s, %s)
        """,
        (full_name, req.last_name, current["username"], current["id"]),
    )
    conn.commit()
    conn.close()

    return {"customer_name": full_name, "registered_by": current["username"]}


@app.get("/get-customers")
def get_customers(authorization: str | None = Header(default=None)):
    _ = get_current_user(authorization)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT c.id,
               c.full_name,
               c.last_name,
               COALESCE(u.username, c.registered_by) AS registered_by
        FROM customers c
        LEFT JOIN users u ON u.id = c.registered_by_user_id
        ORDER BY c.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


@app.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    req.username = validate_username(req.username)
    req.email = validate_email(req.email)

    # do not leak more details than needed
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, email FROM users WHERE username = %s", (req.username,))
    u = cur.fetchone()
    conn.close()

    if not u or u["email"] != req.email:
        raise HTTPException(status_code=404, detail="User or Email incorrect")

    # Create reset token (SHA-256 hash stored in DB; raw sent to user)
    raw_token = secrets.token_urlsafe(24)
    token_hash = sha256_hex(raw_token)
    now = utcnow_naive()
    expires = now + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
        (u["id"], token_hash, expires),
    )
    conn.commit()
    conn.close()

    send_email_best_effort(
        to_email=req.email,
        subject="Communication_LTD - Password Reset",
        body=f"קוד איפוס הסיסמה שלך הוא:\n{raw_token}\n\nבתוקף עד: {expires} (UTC)\n",
    )

    # Demo-friendly: return token only if DEV_RETURN_RESET_TOKEN=1
    if os.getenv("DEV_RETURN_RESET_TOKEN", "1") == "1":
        return {"message": "Reset token created", "reset_token": raw_token, "expires_at": str(expires)}

    return {"message": "If the details are correct, a reset token was sent to the email."}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    req.username = validate_username(req.username)

    is_strong, msg = validate_password_strength(req.new_password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE username = %s", (req.username,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    token_hash = sha256_hex(req.token)
    cur.execute(
        """
        SELECT id, expires_at, used
        FROM password_reset_tokens
        WHERE user_id = %s AND token_hash = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (user["id"], token_hash),
    )
    t = cur.fetchone()

    if not t or t["used"] or t["expires_at"] <= utcnow_naive():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    # history check
    cur.execute(
        "SELECT password_hash, salt FROM password_history WHERE user_id = %s ORDER BY id DESC LIMIT %s",
        (user["id"], PASSWORD_CONFIG["history_limit"]),
    )
    history = cur.fetchall()
    for entry in history:
        if verify_password_hmac(req.new_password, entry["password_hash"], entry["salt"]):
            conn.close()
            raise HTTPException(status_code=400, detail="לא ניתן להשתמש בסיסמה שהייתה בשימוש לאחרונה")

    new_hash, new_salt = hash_password_hmac(req.new_password)

    cur2 = conn.cursor()
    cur2.execute(
        """
        UPDATE users
        SET password_hash = %s,
            salt = %s,
            failed_attempts = 0,
            is_locked = 0,
            locked_until = NULL
        WHERE id = %s
        """,
        (new_hash, new_salt, user["id"]),
    )
    cur2.execute(
        "INSERT INTO password_history (user_id, password_hash, salt) VALUES (%s, %s, %s)",
        (user["id"], new_hash, new_salt),
    )
    cur2.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = %s", (t["id"],))
    conn.commit()
    conn.close()

    # Revoke active sessions after reset
    revoke_all_tokens(user["id"])

    return {"message": "Password reset successful"}