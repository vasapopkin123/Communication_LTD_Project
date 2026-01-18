from settings import EMAIL_ADDRESS, EMAIL_PASSWORD

PASSWORD_CONFIG = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_numbers": True,
    "require_special": True,
    "history_limit": 3,
    "max_login_attempts": 3,
    "lock_minutes": 30, 
    "forbidden_words": ["123456", "password", "communication", "admin", "12345678"]
}

SECRET_KEY = "LTD_SECRET_KEY_2025"

smtp_server = "smtp.gmail.com"
smtp_port = 587
sender_email = EMAIL_ADDRESS
sender_password = EMAIL_PASSWORD
subject = "Your Recovery Password"