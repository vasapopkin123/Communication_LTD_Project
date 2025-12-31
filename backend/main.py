import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import hash_password_hmac, verify_password_hmac, validate_password_strength, generate_sha1_token
from config import PASSWORD_CONFIG
import time

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
conn.close()

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class ChangePassword(BaseModel):
    username: str
    old_password: str
    new_password: str

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
    
    if db_user['is_locked']:
        conn.close()
        raise HTTPException(status_code=403, detail="החשבון נעול! פנה למנהל המערכת")

    if verify_password_hmac(user.password, db_user['password_hash'], db_user['salt']):
        cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = %s", (db_user['id'],))
        conn.commit()
        conn.close()
        return {"message": "Success"}
    else:
        new_attempts = db_user['failed_attempts'] + 1
        lock_status = new_attempts >= PASSWORD_CONFIG["max_login_attempts"]
        cursor.execute("UPDATE users SET failed_attempts = %s, is_locked = %s WHERE id = %s", 
                       (new_attempts, lock_status, db_user['id']))
        conn.commit()
        conn.close()
        error_msg = "סיסמה שגויה" if not lock_status else "החשבון ננעל עקב 3 ניסיונות כושלים"
        raise HTTPException(status_code=401, detail=error_msg)

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
    return {"sha1_token": generate_sha1_token()}

@app.post("/add-customer")
def add_customer(name: str, registered_by: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO customers (full_name, registered_by) VALUES (%s, %s)", (name, registered_by))
    conn.commit()
    conn.close()
    return {"customer_name": name, "registered_by": registered_by}

@app.get("/get-customers")
def get_customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers")
    result = cursor.fetchall()
    conn.close()
    return result