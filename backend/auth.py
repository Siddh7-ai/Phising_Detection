""""
Authentication routes
"""
from flask import Blueprint, request, jsonify
import re
from database import User
from middleware import create_jwt_token, token_required, validate_password_strength
from flask_cors import CORS

auth_bp = Blueprint('auth', __name__)
CORS(auth_bp)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username"""
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, None

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == "OPTIONS":
        return "", 200
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Validate username
        is_valid, error = validate_username(username)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        is_valid, error = validate_password_strength(password)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Create user
        user = User.create(username, email, password)
        
        # Generate token
        token = create_jwt_token(user['id'])
        
        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            },
            'token': token
        }), 201
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 409
    
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return "", 200
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Verify credentials
        user = User.verify_password(email, password)
        
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate token
        token = create_jwt_token(user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            },
            'token': token
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 423
    
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get user profile"""
    return jsonify({'user': current_user}), 200

@auth_bp.route('/validate-token', methods=['GET'])
@token_required
def validate_token(current_user):
    """Validate JWT token"""
    return jsonify({
        'valid': True,
        'user': {
            'id': current_user['id'],
            'username': current_user['username']
        }
    }), 200
