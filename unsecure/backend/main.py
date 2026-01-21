
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

# יצירת טבלאות
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
cursor.execute("CREATE TABLE IF NOT EXISTS customers (id INT AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(255) NOT NULL, registered_by VARCHAR(255) NOT NULL)")
conn.close()

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


@app.post("/login")
def login(user: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    
    
    query = f"SELECT * FROM users WHERE username = '{user.username}'"
    cursor.execute(query) 
    
    db_user = cursor.fetchone()
    conn.close()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if verify_password_hmac(user.password, db_user['password_hash'], db_user['salt']):
        return {"message": "Success"}
    else:
        raise HTTPException(status_code=401, detail="Wrong password")

@app.post("/register")
def register(user: UserRegister):

    is_strong, msg = validate_password_strength(user.password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    pwd_hash, salt = hash_password_hmac(user.password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = f"INSERT INTO users (username, email, password_hash, salt) VALUES ('{user.username}', '{user.email}', '{pwd_hash}', '{salt}')"
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
    cursor.execute(f"INSERT INTO customers (full_name, registered_by) VALUES ('{name}', '{registered_by}')")
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
        html_content += f"<li>לקוח: {customer['full_name']} | נרשם ע'י: {customer['registered_by']}</li>"
    html_content += "</ul><a href='/'>חזרה</a></body></html>"
    
    return html_content


