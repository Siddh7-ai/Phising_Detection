""""
JWT middleware for authentication
"""
import jwt
from functools import wraps
from flask import request, jsonify
from config import Config
from database import User

def create_jwt_token(user_id):
    """Create JWT token"""
    from datetime import datetime
    
    payload = {
        'user_id': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + Config.JWT_EXPIRATION_DELTA
    }
    
    token = jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    """Decode JWT token"""
    try:
        payload = jwt.decode(
            token, 
            Config.JWT_SECRET_KEY, 
            algorithms=[Config.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def token_required(f):
    """Decorator for protected routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            payload = decode_jwt_token(token)
            user_id = payload['user_id']
            
            current_user = User.get_by_id(user_id)
            if not current_user:
                return jsonify({'error': 'User not found or inactive'}), 401
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Token validation failed'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters"
    
    if Config.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if Config.REQUIRE_NUMBER and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    if Config.REQUIRE_SPECIAL_CHAR and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    
    return True, None