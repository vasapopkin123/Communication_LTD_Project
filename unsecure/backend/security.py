import hashlib
import hmac
import os
import re
from config import SECRET_KEY, PASSWORD_CONFIG

def validate_password_strength(password: str):
    # 1. בדיקת אורך
    if len(password) < PASSWORD_CONFIG["min_length"]:
        return False, f"הסיסמה חייבת להיות לפחות {PASSWORD_CONFIG['min_length']} תווים"
    
    # 2. בדיקת אות גדולה
    if PASSWORD_CONFIG["require_upper"] and not re.search(r"[A-Z]", password):
        return False, "הסיסמה חייבת להכיל לפחות אות גדולה אחת (A-Z)"
        
    # 3. בדיקת אות קטנה
    if PASSWORD_CONFIG["require_lower"] and not re.search(r"[a-z]", password):
        return False, "הסיסמה חייבת להכיל לפחות אות קטנה אחת (a-z)"
        
    # 4. בדיקת מספרים
    if PASSWORD_CONFIG["require_numbers"] and not re.search(r"\d", password):
        return False, "הסיסמה חייבת להכיל לפחות ספרה אחת (0-9)"
        
    # 5. בדיקת תווים מיוחדים
    if PASSWORD_CONFIG["require_special"] and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "הסיסמה חייבת להכיל לפחות תו מיוחד אחד (!@#$%^&*)"

    # 6. מניעת שימוש במילון
    for word in PASSWORD_CONFIG["forbidden_words"]:
        if word in password.lower():
            return False, f"הסיסמה מכילה מילה אסורה לשימוש: {word}"
            
    return True, "Strong password"

def hash_password_hmac(password: str, salt: str = None):
    if salt is None:
        salt = os.urandom(16).hex()
    digest = hmac.new(
        SECRET_KEY.encode(), 
        (password + salt).encode(), 
        hashlib.sha256
    ).hexdigest()
    return digest, salt

def verify_password_hmac(plain_password, stored_hash, salt):
    new_hash, _ = hash_password_hmac(plain_password, salt)
    return hmac.compare_digest(new_hash, stored_hash)

def generate_sha1_token():
    random_data = os.urandom(20)
    return hashlib.sha1(random_data).hexdigest()