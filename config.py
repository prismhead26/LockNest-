import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24).hex())
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'locknest.db')
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 30))

    # Security headers
    SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT * 60
