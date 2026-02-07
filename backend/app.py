"""
PhishGuard AI - Flask Backend with Authentication and Phishing Detection
Combined Version 3.0.0

Features:
- User Authentication (Register, Login, Profile)
- JWT Token Management & Protected Routes
- Rate Limiting
- Secure PYTHONPATH handling
- CORS support with credentials
- Health check endpoint
- URL validation
- Feature extraction
- ML inference with predict_proba
- Probability-based classification
- Risk level mapping
- Explainable AI (risk factors)
- Scan history logging (CSV + Database)
- User statistics
- EXTENSION-COMPATIBLE ENDPOINT: /api/scan
- FRONTEND-ENHANCED ENDPOINT: /check_url with timestamp & model
- AUTHENTICATED ENDPOINT: /api/predict-authenticated
- PUBLIC ENDPOINT: /api/predict
- BUG FIX: Handle risk_factors as list or dict
"""

import os
import sys
import csv
import joblib
import traceback
import pickle
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ------------------------------------------------------------------
# PATH FIX (CRITICAL)
# ------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Add parent directory to path to import ai modules
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# ------------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------------

from ai.features import extract_features, explain_features

# Import configuration
from config import Config

# Import database
from database import init_db, ScanHistory

# Import authentication
from auth import auth_bp
from middleware import token_required

# ------------------------------------------------------------------
# APP INITIALIZATION
# ------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS with credentials support
CORS(app, 
     origins=Config.CORS_ORIGINS,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'])

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT],
    storage_uri=Config.RATELIMIT_STORAGE_URL
)

# Register authentication blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')

# Initialize database on startup
with app.app_context():
    init_db()

# ------------------------------------------------------------------
# MODEL & LOG PATHS
# ------------------------------------------------------------------

MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
LOG_PATH = os.path.join(BASE_DIR, "logs", "scan_history.csv")

# Try loading with joblib first, then pickle as fallback
try:
    model = joblib.load(MODEL_PATH)
    print("[✓] ML model loaded successfully with joblib")
except Exception as e1:
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        print("[✓] ML model loaded successfully with pickle")
    except Exception as e2:
        print(f"[✗] Failed to load model with joblib: {e1}")
        print(f"[✗] Failed to load model with pickle: {e2}")
        model = None

# ------------------------------------------------------------------
# CONFIDENCE THRESHOLDS (PROBABILITY-BASED)
# ------------------------------------------------------------------

PHISHING_THRESHOLD = 0.75     # ≥ 75% → Phishing
SUSPICIOUS_THRESHOLD = 0.40   # 40–75% → Suspicious
# < 40% → Legitimate

# ------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------

def classify_by_confidence(confidence: float):
    """
    Final classification based ONLY on phishing probability.
    
    Returns:
        tuple: (label, risk_level)
        - label: "Phishing", "Suspicious", or "Legitimate"
        - risk_level: "High", "Medium", or "Low"
    """
    if confidence >= PHISHING_THRESHOLD:
        return "Phishing", "High"
    elif confidence >= SUSPICIOUS_THRESHOLD:
        return "Suspicious", "Medium"
    else:
        return "Legitimate", "Low"


def log_scan(url: str, label: str, confidence: float, risk: str):
    """
    Append scan details to CSV history log.
    
    Args:
        url: The URL that was scanned
        label: Classification result
        confidence: Phishing probability (0-1)
        risk: Risk level (Low/Medium/High)
    """
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    file_exists = os.path.exists(LOG_PATH)

    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp",
                "url",
                "label",
                "phishing_probability",
                "risk_level"
            ])
        writer.writerow([
            datetime.utcnow().isoformat(),
            url,
            label,
            round(confidence * 100, 2),
            risk
        ])


def extract_metrics_for_extension(url: str, risk_factors):
    """
    Convert risk_factors to extension-friendly metrics format.
    ✅ FIX: Handle risk_factors as either dict or list
    
    Args:
        url: The URL being analyzed
        risk_factors: Either dict or list of risk factors
        
    Returns:
        dict: Metrics in extension-compatible format
    """
    from urllib.parse import urlparse
    
    # Parse URL
    parsed = urlparse(url)
    
    # ✅ FIXED: Handle risk_factors as either dict or list
    if isinstance(risk_factors, dict):
        domain_age = risk_factors.get("domain_age", "Unknown")
        suspicious_keywords = risk_factors.get("suspicious_keywords", False)
    else:
        # If risk_factors is a list or other type, use defaults
        domain_age = "Unknown"
        suspicious_keywords = False
    
    # Check HTTPS
    https = parsed.scheme == "https"
    
    # URL length
    url_length = len(url)
    
    # Check if IP address is used
    has_ip = any(char.isdigit() for char in parsed.netloc.replace(".", ""))
    
    return {
        "domain_age": domain_age,
        "https": https,
        "url_length": url_length,
        "has_ip": has_ip,
        "suspicious_keywords": suspicious_keywords
    }


def get_model_name():
    """
    Get the ML model name.
    
    Returns:
        str: Model name (default "Random Forest")
    """
    # You can make this dynamic based on actual model type
    # For now, returning the known model name
    return "Random Forest"


def predict_url(url):
    """
    Core ML prediction logic used across different endpoints.
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: Prediction results with url, prediction, confidence, risk_level
    """
    try:
        # Extract features (use existing feature extraction)
        features = extract_features(url)
        
        # Predict using model
        if model:
            prediction = model.predict([features])[0]
            probabilities = model.predict_proba([features])[0]
            phishing_probability = float(probabilities[1])  # P(phishing)
            
            # Map prediction to categories using confidence thresholds
            label, risk_level = classify_by_confidence(phishing_probability)
            
            result = {
                'url': url,
                'prediction': label,
                'confidence': float(phishing_probability),
                'risk_level': risk_level.lower()
            }
            
            return result
        else:
            # Fallback if model not loaded
            return {
                'url': url,
                'prediction': 'Unknown',
                'confidence': 0.0,
                'risk_level': 'unknown',
                'error': 'Model not loaded'
            }
    
    except Exception as e:
        print(f"Prediction error: {e}")
        traceback.print_exc()
        return None

# ------------------------------------------------------------------
# PUBLIC ROUTES (NO AUTH REQUIRED)
# ------------------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify API is running.
    """
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard AI API",
        "message": "Phishing Detection API with Authentication is live",
        "version": "3.0.0",
        "endpoints": {
            "authentication": {
                "register": "/auth/register (POST)",
                "login": "/auth/login (POST)",
                "profile": "/auth/profile (GET) - Protected",
                "validate_token": "/auth/validate-token (GET) - Protected"
            },
            "phishing_detection_public": {
                "predict": "/api/predict (POST) - Public, rate limited 30/min",
                "scan": "/api/scan (POST) - Extension compatible",
                "check_url": "/check_url (POST) - Frontend & legacy"
            },
            "phishing_detection_authenticated": {
                "predict_authenticated": "/api/predict-authenticated (POST) - Protected, saves history, 60/min",
                "history": "/api/history (GET) - Protected, get scan history",
                "stats": "/api/stats (GET) - Protected, get user statistics"
            }
        },
        "model_loaded": model is not None,
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/api/predict', methods=['POST'])
@limiter.limit("30 per minute")
def predict():
    """
    Public prediction endpoint (for browser extension without auth)
    No authentication required
    Rate limited to 30 requests per minute
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400
        
        # Perform prediction
        result = predict_url(url)
        
        if not result:
            return jsonify({'error': 'Prediction failed'}), 500
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"Prediction error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Prediction failed'}), 500


@app.route("/api/scan", methods=["POST", "OPTIONS"])
@limiter.limit("30 per minute")
def api_scan():
    """
    EXTENSION-COMPATIBLE ENDPOINT
    
    Used by Chrome extension for phishing detection.
    No authentication required, public endpoint.
    
    Request Body:
        {
            "url": "https://example.com"
        }
    
    Response:
        {
            "url": "https://example.com",
            "classification": "Phishing" | "Suspicious" | "Legitimate",
            "confidence": 85.5,  // 0-100
            "model": "Random Forest",
            "metrics": {
                "domain_age": "Unknown",
                "https": true,
                "url_length": 23,
                "has_ip": false,
                "suspicious_keywords": false
            },
            "timestamp": "2026-02-07 14:30:45"
        }
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return "", 200
    
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field missing."}), 400

    url = data["url"].strip()

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        # ----------------------------
        # Feature extraction
        # ----------------------------
        features = extract_features(url)

        # ----------------------------
        # ML Prediction
        # ----------------------------
        probabilities = model.predict_proba([features])[0]
        phishing_probability = float(probabilities[1])  # P(phishing)

        # ----------------------------
        # Classification
        # ----------------------------
        label, risk_level = classify_by_confidence(phishing_probability)

        # ----------------------------
        # Explainable AI
        # ----------------------------
        risk_factors = explain_features(url)
        
        # Convert to extension format (with bug fix)
        metrics = extract_metrics_for_extension(url, risk_factors)

        # ----------------------------
        # Logging to CSV
        # ----------------------------
        log_scan(
            url=url,
            label=label,
            confidence=phishing_probability,
            risk=risk_level
        )

        # ----------------------------
        # EXTENSION-COMPATIBLE RESPONSE
        # ----------------------------
        return jsonify({
            "url": url,
            "classification": label,  # "Phishing", "Suspicious", or "Legitimate"
            "confidence": round(phishing_probability * 100, 2),  # 0-100
            "model": get_model_name(),
            "metrics": metrics,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    except Exception as e:
        print("=" * 60)
        print("ERROR IN /api/scan:")
        print(traceback.format_exc())
        print("=" * 60)
        
        return jsonify({
            "error": "Failed to analyze URL",
            "details": str(e)
        }), 500


@app.route("/check_url", methods=["POST"])
def check_url():
    """
    ENHANCED FRONTEND ENDPOINT
    
    Used by web frontend for phishing detection.
    No authentication required, public endpoint.
    Now includes additional fields for enhanced frontend features.
    
    Request Body:
        {
            "url": "https://example.com"
        }
    
    Response:
        {
            "url": "https://example.com",
            "label": "PHISHING" | "SUSPICIOUS" | "LEGITIMATE",
            "phishing_probability": 85.5,  // 0-100
            "risk_level": "High" | "Medium" | "Low",
            "risk_factors": ["Long URL", "No HTTPS", ...],
            "model": "Random Forest",
            "timestamp": "2026-02-07T14:30:45.123456",
            "url_length": 45
        }
    """
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field missing."}), 400

    url = data["url"].strip()

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        # ----------------------------
        # Feature extraction
        # ----------------------------
        features = extract_features(url)

        # ----------------------------
        # ML Prediction
        # ----------------------------
        probabilities = model.predict_proba([features])[0]
        phishing_probability = float(probabilities[1])  # P(phishing)

        # ----------------------------
        # Classification
        # ----------------------------
        label, risk_level = classify_by_confidence(phishing_probability)

        # ----------------------------
        # Explainable AI
        # ----------------------------
        risk_factors = explain_features(url)

        # ----------------------------
        # Logging to CSV
        # ----------------------------
        log_scan(
            url=url,
            label=label,
            confidence=phishing_probability,
            risk=risk_level
        )

        # ----------------------------
        # ENHANCED FRONTEND RESPONSE
        # ----------------------------
        return jsonify({
            "url": url,
            "label": label.upper(),  # Uppercase for consistency (PHISHING, SUSPICIOUS, LEGITIMATE)
            "phishing_probability": round(phishing_probability * 100, 2),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            
            # ✅ NEW FIELDS FOR ENHANCED FRONTEND:
            "model": get_model_name(),
            "timestamp": datetime.now().isoformat(),
            "url_length": len(url)
        }), 200

    except Exception as e:
        print("=" * 60)
        print("ERROR IN /check_url:")
        print(traceback.format_exc())
        print("=" * 60)
        
        return jsonify({
            "error": "Failed to analyze URL",
            "details": str(e)
        }), 500

# ------------------------------------------------------------------
# AUTHENTICATED ROUTES (REQUIRE JWT TOKEN)
# ------------------------------------------------------------------

@app.route('/api/predict-authenticated', methods=['POST'])
@token_required
@limiter.limit("60 per minute")
def predict_authenticated(current_user):
    """
    Authenticated prediction - saves to user history in database
    Protected route - requires valid JWT token
    Rate limited to 60 requests per minute for authenticated users
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400
        
        # Perform prediction
        result = predict_url(url)
        
        if not result:
            return jsonify({'error': 'Prediction failed'}), 500
        
        # Save to user history in database
        try:
            ScanHistory.add_scan(
                user_id=current_user['id'],
                url=result['url'],
                prediction=result['prediction'],
                confidence=result['confidence'],
                risk_level=result['risk_level']
            )
            result['saved'] = True
        except Exception as e:
            print(f"Failed to save scan history: {e}")
            traceback.print_exc()
            result['saved'] = False
        
        # Also log to CSV
        log_scan(
            url=result['url'],
            label=result['prediction'],
            confidence=result['confidence'],
            risk=result['risk_level']
        )
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"Authenticated prediction error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Prediction failed'}), 500


@app.route('/api/history', methods=['GET'])
@token_required
@limiter.limit("20 per minute")
def get_history(current_user):
    """
    Get user scan history from database
    Protected route - requires valid JWT token
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 100)  # Max 100 records
        
        history = ScanHistory.get_user_history(current_user['id'], limit)
        
        return jsonify({
            'history': history,
            'count': len(history)
        }), 200
    
    except Exception as e:
        print(f"History retrieval error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Failed to retrieve history'}), 500


@app.route('/api/stats', methods=['GET'])
@token_required
@limiter.limit("10 per minute")
def get_stats(current_user):
    """
    Get user statistics from database
    Protected route - requires valid JWT token
    """
    try:
        stats = ScanHistory.get_user_stats(current_user['id'])
        return jsonify({'stats': stats}), 200
    
    except Exception as e:
        print(f"Stats retrieval error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# ------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PHISHGUARD AI - COMPLETE BACKEND SERVER")
    print("=" * 60)
    print(f"[✓] Version: 3.0.0 (Authentication + Detection Combined)")
    print(f"[✓] Server running on: http://0.0.0.0:5000")
    print("")
    print("🔐 AUTHENTICATION ENDPOINTS:")
    print(f"   • Register: http://localhost:5000/auth/register")
    print(f"   • Login: http://localhost:5000/auth/login")
    print(f"   • Profile: http://localhost:5000/auth/profile (Protected)")
    print(f"   • Validate Token: http://localhost:5000/auth/validate-token (Protected)")
    print("")
    print("🌐 PUBLIC PHISHING DETECTION ENDPOINTS:")
    print(f"   • Public Predict: http://localhost:5000/api/predict (30/min)")
    print(f"   • Extension Scan: http://localhost:5000/api/scan (30/min)")
    print(f"   • Frontend Check: http://localhost:5000/check_url")
    print("")
    print("🔒 AUTHENTICATED PHISHING DETECTION ENDPOINTS:")
    print(f"   • Auth Predict: http://localhost:5000/api/predict-authenticated (60/min)")
    print(f"   • History: http://localhost:5000/api/history (Protected)")
    print(f"   • Stats: http://localhost:5000/api/stats (Protected)")
    print("")
    print(f"[✓] Health check: http://localhost:5000/")
    print(f"[✓] Model loaded: {model is not None}")
    if model is not None:
        print(f"[✓] Model type: {get_model_name()}")
    print(f"[✓] Database initialized")
    print(f"[✓] Rate limiting active")
    print("=" * 60)
    print("\n🎯 COMPLETE FEATURE SET:")
    print("   ✅ User authentication with JWT")
    print("   ✅ Protected routes with token verification")
    print("   ✅ Rate limiting (30/min public, 60/min authenticated)")
    print("   ✅ Database scan history for authenticated users")
    print("   ✅ User statistics tracking")
    print("   ✅ CSV logging for all scans")
    print("   ✅ Enhanced /check_url with model, timestamp, url_length")
    print("   ✅ Extension-compatible /api/scan endpoint")
    print("   ✅ Explainable AI with risk factors")
    print("   ✅ Probability-based classification")
    print("   ✅ CORS support with credentials")
    print("   ✅ Comprehensive error handling")
    print("   ✅ Health check with full endpoint documentation")
    print("=" * 60)
    
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )