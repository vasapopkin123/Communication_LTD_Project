import mysql.connector
import time
import smtplib
import re
from email.mime.text import MIMEText
from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import hash_password_hmac, verify_password_hmac, validate_password_strength, generate_sha1_token
from config import PASSWORD_CONFIG
from pydantic import BaseModel, Field

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    while True:
        try:
            conn = mysql.connector.connect(
                host="mysql",
                user="user",
                password="password",
                database="my_app_db"
            )
            return conn
        except:
            print("Database not ready, retrying in 2 seconds...")
            time.sleep(2)

# יצירת טבלאות עם השדות החדשים
conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        failed_attempts INT DEFAULT 0,
        is_locked BOOLEAN DEFAULT FALSE
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INT AUTO_INCREMENT PRIMARY KEY, 
        full_name VARCHAR(255) NOT NULL, 
        registered_by VARCHAR(255) NOT NULL
    )
""")
try:
    cursor.execute("ALTER TABLE users ADD COLUMN locked_until DATETIME NULL")
    conn.commit()
except mysql.connector.Error:
    pass

try:
    cursor.execute("ALTER TABLE customers ADD COLUMN first_name VARCHAR(255) NULL")
    cursor.execute("ALTER TABLE customers ADD COLUMN last_name VARCHAR(255) NULL")
    cursor.execute("ALTER TABLE customers ADD COLUMN registered_by_user_id INT NULL")
    conn.commit()
except mysql.connector.Error:
    pass
    
conn.close()

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class ChangePassword(BaseModel):
    username: str
    old_password: str
    new_password: str

class CustomerCreate(BaseModel):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str  = Field(min_length=1, max_length=80)
    registered_by_username: str = Field(min_length=1, max_length=255)


def send_email(to_email: str, subject: str, body: str):
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_FROM, [to_email], msg.as_string())


ALLOWED_SORT = {
    "username": "username",
    "email": "email",
    "id": "id",
}

def get_users_sorted(sort_col: str):
    col = ALLOWED_SORT.get(sort_col, "id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"SELECT id, username, email FROM users ORDER BY `{col}`")
    rows = cursor.fetchall()
    conn.close()
    return rows      

AME_RE = re.compile(r"^[A-Za-zא-ת][A-Za-zא-ת \-']{0,79}$")

def validate_name(s: str, field: str):
    if not NAME_RE.match(s):
        raise HTTPException(status_code=400, detail=f"{field} contains invalid characters")

@app.post("/register")
def register(user: UserRegister):
    is_strong, msg = validate_password_strength(user.password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)
    pwd_hash, salt = hash_password_hmac(user.password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)", 
                       (user.username, user.email, pwd_hash, salt))
        user_id = cursor.lastrowid
        # שמירה ראשונית בהיסטוריה
        cursor.execute("INSERT INTO password_history (user_id, password_hash, salt) VALUES (%s, %s, %s)",
                       (user_id, pwd_hash, salt))
        conn.commit()
    except:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally: conn.close()
    return {"message": "Success"}

@app.post("/login")
def login(user: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
    db_user = cursor.fetchone()

    if not db_user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    now = datetime.utcnow()

    if db_user.get("is_locked") and db_user.get("locked_until") is None:
        cursor.execute(
            "UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = %s",
            (db_user["id"],)
        )
        conn.commit()
        # רענון מצב משתמש
        cursor.execute("SELECT * FROM users WHERE id = %s", (db_user["id"],))
        db_user = cursor.fetchone()

    locked_until = db_user.get("locked_until")
    if locked_until and locked_until > now:
        conn.close()
        remaining = int((locked_until - now).total_seconds() // 60) + 1
        raise HTTPException(status_code=403, detail=f"החשבון נעול לעוד {remaining} דקות")

    if locked_until and locked_until <= now:
        cursor.execute(
            "UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = %s",
            (db_user["id"],)
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE id = %s", (db_user["id"],))
        db_user = cursor.fetchone()

    if verify_password_hmac(user.password, db_user["password_hash"], db_user["salt"]):
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE id = %s",
            (db_user["id"],)
        )
        conn.commit()
        conn.close()
        return {"message": "Success"}

    # failed attempt
    new_attempts = db_user["failed_attempts"] + 1
    max_attempts = PASSWORD_CONFIG["max_login_attempts"]  # :contentReference[oaicite:9]{index=9}
    if new_attempts >= max_attempts:
        until = now + timedelta(minutes=PASSWORD_CONFIG["lock_minutes"])
        cursor.execute(
            "UPDATE users SET failed_attempts = %s, is_locked = 1, locked_until = %s WHERE id = %s",
            (new_attempts, until, db_user["id"])
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="החשבון ננעל ל-30 דקות עקב 3 ניסיונות כושלים")

    cursor.execute(
        "UPDATE users SET failed_attempts = %s WHERE id = %s",
        (new_attempts, db_user["id"])
    )
    conn.commit()
    conn.close()
    raise HTTPException(status_code=401, detail="סיסמה שגויה")

@app.post("/change-password")
def change_password(data: ChangePassword):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cursor.fetchone()
    
    if not user or not verify_password_hmac(data.old_password, user['password_hash'], user['salt']):
        conn.close()
        raise HTTPException(status_code=401, detail="Old password incorrect")

    # בדיקת היסטוריה (3 סיסמאות אחרונות)
    cursor.execute("SELECT password_hash, salt FROM password_history WHERE user_id = %s ORDER BY id DESC LIMIT %s",
                   (user['id'], PASSWORD_CONFIG["history_limit"]))
    history = cursor.fetchall()
    for entry in history:
        if verify_password_hmac(data.new_password, entry['password_hash'], entry['salt']):
            conn.close()
            raise HTTPException(status_code=400, detail="לא ניתן להשתמש בסיסמה שהייתה בשימוש לאחרונה")

    is_strong, msg = validate_password_strength(data.new_password)
    if not is_strong: 
        conn.close()
        raise HTTPException(status_code=400, detail=msg)

    new_hash, new_salt = hash_password_hmac(data.new_password)
    cursor.execute("UPDATE users SET password_hash = %s, salt = %s WHERE id = %s", (new_hash, new_salt, user['id']))
    cursor.execute("INSERT INTO password_history (user_id, password_hash, salt) VALUES (%s, %s, %s)",
                   (user['id'], new_hash, new_salt))
    conn.commit()
    conn.close()
    return {"message": "Updated"}

@app.post("/forgot-password")
def forgot_password(username: str, email: str):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or user['email'] != email:
        raise HTTPException(status_code=404, detail="User or Email incorrect")

    token = generate_sha1_token()
    send_email(
        to_email=email,
        subject="Comunication_LTD - Password Reset Token",
        body=f"הטוקן לאיפוס סיסמה הוא:\n\n{token}\n\nהזן אותו במסך איפוס הסיסמה."
    )

    return {"message": "אם הפרטים נכונים, נשלח טוקן למייל"}


@app.post("/add-customer")
def add_customer(data: CustomerCreate):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    validate_name(data.first_name, "first_name")
    validate_name(data.last_name, "last_name")

    cursor.execute("SELECT id FROM users WHERE username = %s", (data.registered_by_username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=400, detail="registered_by user not found")

    cursor2 = conn.cursor()
    cursor2.execute(
        "INSERT INTO customers (first_name, last_name, registered_by_user_id) VALUES (%s, %s, %s)",
        (data.first_name, data.last_name, user["id"])
    )
    conn.commit()
    conn.close()

    return {
        "customer_first_name": data.first_name,
        "customer_last_name": data.last_name,
        "registered_by_user_id": user["id"]
    }

@app.get("/get-customers")
def get_customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT c.id, c.first_name, c.last_name, c.registered_by_user_id
        FROM customers c
    """)
    result = cursor.fetchall()
    conn.close()

    # ✅ Encode ביציאה (כדי שגם אם פרונט משתמש innerHTML – יצמצם נזק)
    for r in result:
        r["first_name"] = html_encode(r.get("first_name") or "")
        r["last_name"]  = html_encode(r.get("last_name") or "")
    return result