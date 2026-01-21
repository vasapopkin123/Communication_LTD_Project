
import os
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
import smtplib
import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import hash_password_hmac, verify_password_hmac, validate_password_strength, generate_sha1_token
from config import PASSWORD_CONFIG
import time
from fastapi.responses import HTMLResponse


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

B_HOST = os.getenv("DB_HOST", "my_mysql_db_not_secure")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_NAME = os.getenv("DB_NAME", "my_app_db")

# If your MySQL is slow to start, you can let the API retry a few times.
DB_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_RETRIES", "20"))
DB_CONNECT_SLEEP_SECONDS = int(os.getenv("DB_CONNECT_SLEEP_SECONDS", "2"))

_DB_SCHEMA_READY = False


def _connect_db_once():
    # mysql-connector: use connection_timeout to avoid hanging sockets
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        connection_timeout=5,
    )


def _ensure_db_schema():
    """Create tables/columns once. Never block import-time."""
    global _DB_SCHEMA_READY
    if _DB_SCHEMA_READY:
        return

    # Try a few times (DB may still be starting)
    last_err = None
    for _ in range(DB_CONNECT_RETRIES):
        try:
            conn = _connect_db_once()
            break
        except Exception as e:
            last_err = e
            print(f"DB not ready ({type(e).__name__}). Retrying in {DB_CONNECT_SLEEP_SECONDS}s...")
            time.sleep(DB_CONNECT_SLEEP_SECONDS)
    else:
        raise RuntimeError(f"DB connection failed after retries: {last_err}")

    cursor = conn.cursor()

    # users table
    cursor.execute(
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

    # ---- schema upgrades for time-based lock + auth token TTL ----
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN lock_until DATETIME NULL")
    except Exception:
        pass

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            token VARCHAR(40) NOT NULL,
            expires_at DATETIME NOT NULL,
            revoked BOOLEAN DEFAULT FALSE
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            registered_by VARCHAR(255) NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            token VARCHAR(40) NOT NULL,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT FALSE
        )
        """
    )

    conn.commit()
    conn.close()
    _DB_SCHEMA_READY = True


def get_db_connection():
    """Get a DB connection for request handlers; returns 503 if DB is down."""
    try:
        _ensure_db_schema()
        return _connect_db_once()
    except Exception as e:
        # Print full error to container logs for debugging, but return a clean message to client
        print("DB connection/schema error:", repr(e))
        raise HTTPException(status_code=503, detail="Database unavailable")

def send_email_best_effort(to_email: str, subject: str, body: str) -> bool:

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")
    from_addr = os.getenv("SMTP_FROM") or user

    if not host or not user or not pwd or not from_addr:
        # Demo-friendly fallback
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

    print("Sending email to:", to_email)
    return True

LOCK_MINUTES = 30
AUTH_TOKEN_TTL_HOURS = 12
RESET_TOKEN_TTL_MINUTES = 30



# -----------------------------
# Models
# -----------------------------
class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class ResetPasswordRequest(BaseModel):
    username: str
    token: str
    new_password: str


# -----------------------------
# Endpoints
# -----------------------------
@app.post("/login")
def login(user: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    now = datetime.utcnow()

    # NOTE: non-secure on purpose (string concat) to demonstrate SQLi
    query = f"SELECT * FROM users WHERE username = '{user.username}'"
    cursor.execute(query)
    db_user = cursor.fetchone()

    if not db_user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Support both old boolean lock and new time-based lock
    lock_until = db_user.get("lock_until")
    is_locked = bool(db_user.get("is_locked"))

    # If user was locked (legacy) but no lock_until exists, start a time-based lock now
    if is_locked and not lock_until:
        lock_until = now + timedelta(minutes=LOCK_MINUTES)
        lock_str = lock_until.strftime("%Y-%m-%d %H:%M:%S")
        cur_upd = conn.cursor()
        # NOTE: non-secure on purpose (string concat)
        cur_upd.execute(
            f"UPDATE users SET lock_until = '{lock_str}', is_locked = 1 WHERE username = '{db_user['username']}'"
        )
        conn.commit()

    # Auto-unlock if time passed
    if lock_until and isinstance(lock_until, datetime) and lock_until <= now:
        cur_upd = conn.cursor()
        # NOTE: non-secure on purpose (string concat)
        cur_upd.execute(
            f"UPDATE users SET failed_attempts = 0, is_locked = 0, lock_until = NULL WHERE username = '{db_user['username']}'"
        )
        conn.commit()
        lock_until = None
        is_locked = False

    # Still locked?
    if lock_until and isinstance(lock_until, datetime) and lock_until > now:
        remaining = int((lock_until - now).total_seconds())
        remaining_minutes = max(1, (remaining + 59) // 60)
        conn.close()
        raise HTTPException(
            status_code=423,
            detail=f"Account locked. Try again in {remaining_minutes} minutes",
        )

    # Verify password
    if verify_password_hmac(user.password, db_user["password_hash"], db_user["salt"]):
        # Successful login resets attempts + unlock
        cur_upd = conn.cursor()
        # NOTE: non-secure on purpose (string concat)
        cur_upd.execute(
            f"UPDATE users SET failed_attempts = 0, is_locked = 0, lock_until = NULL WHERE username = '{db_user['username']}'"
        )

        # Optional: create an auth token (TTL 12h) like secure version.
        auth_token = generate_sha1_token()
        expires = now + timedelta(hours=AUTH_TOKEN_TTL_HOURS)
        expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

        cur_upd.execute(
            f"UPDATE auth_tokens SET revoked = 1 WHERE username = '{db_user['username']}'"
        )
        cur_upd.execute(
            f"INSERT INTO auth_tokens (username, token, expires_at, revoked) "
            f"VALUES ('{db_user['username']}', '{auth_token}', '{expires_str}', 0)"
        )

        conn.commit()
        conn.close()
        return {"message": "Success", "auth_token": auth_token, "auth_expires_at": expires_str}

    # Wrong password: increment attempts and lock if needed
    attempts = int(db_user.get("failed_attempts") or 0) + 1

    cur_upd = conn.cursor()
    if attempts >= PASSWORD_CONFIG["max_login_attempts"]:
        lock_until = now + timedelta(minutes=LOCK_MINUTES)
        lock_str = lock_until.strftime("%Y-%m-%d %H:%M:%S")
        # NOTE: non-secure on purpose (string concat)
        cur_upd.execute(
            f"UPDATE users SET failed_attempts = {attempts}, is_locked = 1, lock_until = '{lock_str}' "
            f"WHERE username = '{db_user['username']}'"
        )
        conn.commit()
        conn.close()
        raise HTTPException(
            status_code=423,
            detail=f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes",
        )
    else:
        # NOTE: non-secure on purpose (string concat)
        cur_upd.execute(
            f"UPDATE users SET failed_attempts = {attempts} WHERE username = '{db_user['username']}'"
        )
        conn.commit()
        conn.close()
        remaining = PASSWORD_CONFIG["max_login_attempts"] - attempts
        raise HTTPException(
            status_code=401,
            detail=f"Wrong password ({remaining} attempts left)",
        )


@app.post("/register")
def register(user: UserRegister):
    is_strong, msg = validate_password_strength(user.password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    pwd_hash, salt = hash_password_hmac(user.password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # NOTE: non-secure on purpose (string concat) to demonstrate SQLi
        query = (
            f"INSERT INTO users (username, email, password_hash, salt) "
            f"VALUES ('{user.username}', '{user.email}', '{pwd_hash}', '{salt}')"
        )
        cursor.execute(query)
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

    return {"message": "Success"}


@app.post("/add-customer")
def add_customer(name: str, registered_by: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    # NOTE: non-secure on purpose (string concat) to demonstrate SQLi
    cursor.execute(
        f"INSERT INTO customers (full_name, registered_by) VALUES ('{name}', '{registered_by}')"
    )
    conn.commit()
    conn.close()

    return {"customer_name": name}


@app.get("/get-customers", response_class=HTMLResponse)
def get_customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers")
    result = cursor.fetchall()
    conn.close()

    html_content = "<html><body dir='rtl'><h1>רשימת לקוחות</h1><ul>"
    for customer in result:
        html_content += (
            f"<li>לקוח: {customer['full_name']} | נרשם ע'י: {customer['registered_by']}</li>"
        )
    html_content += "</ul><a href='/'>חזרה</a></body></html>"

    return html_content



@app.post("/forgot-password")
def forgot_password(username: str, email: str):

    username = (username or "").strip()
    email = (email or "").strip()

    if not username or not email:
        raise HTTPException(status_code=400, detail="Missing username/email")

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute(f"SELECT * FROM users WHERE username = '{username}' AND email = '{email}'")
    u = cur.fetchone()

    if not u:
        conn.close()
        raise HTTPException(status_code=404, detail="User or Email incorrect")

    token = generate_sha1_token()  # SHA-1 token (hex)
    expires = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
    expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

    # store token
    cur2 = conn.cursor()
    cur2.execute(
        f"INSERT INTO password_reset_tokens (username, token, expires_at, used) "
        f"VALUES ('{username}', '{token}', '{expires_str}', 0)"
    )
    conn.commit()
    conn.close()

    send_email_best_effort(
        to_email=email,
        subject="Communication_LTD - Password Reset",
        body=(
            "קוד איפוס הסיסמה שלך הוא:\n"
            f"{token}\n\n"
            f"בתוקף עד: {expires_str} (UTC)\n"
        ),
    )

    # Demo-friendly: return token for the UI to show (your forgot.html expects sha1_token)
    return {"message": "Token created", "sha1_token": token, "expires_at": expires_str}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    username = (req.username or "").strip()
    token = (req.token or "").strip()

    is_strong, msg = validate_password_strength(req.new_password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    now = datetime.utcnow()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # NOTE: non-secure on purpose (string concat) to demonstrate SQLi
    cur.execute(
        f"SELECT * FROM password_reset_tokens "
        f"WHERE username = '{username}' AND token = '{token}' "
        f"ORDER BY id DESC LIMIT 1"
    )
    t = cur.fetchone()

    if not t:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if t.get("used"):
        conn.close()
        raise HTTPException(status_code=400, detail="Reset token already used")

    # expires_at is returned as datetime by mysql-connector in dict mode
    expires_at = t.get("expires_at")
    if expires_at and expires_at <= now:
        conn.close()
        raise HTTPException(status_code=400, detail="Reset token expired")

    # update password
    new_hash, new_salt = hash_password_hmac(req.new_password)

    cur2 = conn.cursor()
    # NOTE: non-secure on purpose (string concat) to demonstrate SQLi
    cur2.execute(
        f"UPDATE users SET password_hash = '{new_hash}', salt = '{new_salt}' WHERE username = '{username}'"
    )
    cur2.execute(f"UPDATE password_reset_tokens SET used = 1 WHERE id = {int(t['id'])}")
    conn.commit()
    conn.close()

    return {"message": "Password reset successful", "reset_at": now_str}
