""""
Configuration management for PhishGuard AI
"""
import os
from datetime import timedelta

class Config:
    # Security secrets (change these!)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-jwt-secret-change-in-production'
    
    # JWT settings
    JWT_EXPIRATION_DELTA = timedelta(hours=1)
    JWT_ALGORITHM = 'HS256'
    
    # Database path (relative to backend folder)
    DATABASE_PATH = 'phishguard.db'
    
    # CORS
    CORS_ORIGINS = ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5500']
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_AUTH = "5 per minute"
    
    # Password policy
    MIN_PASSWORD_LENGTH = 8
    REQUIRE_SPECIAL_CHAR = True
    REQUIRE_UPPERCASE = True
    REQUIRE_NUMBER = True