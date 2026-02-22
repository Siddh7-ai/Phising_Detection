"""
PhishGuard AI - Fully Merged Backend
Version: 6.1.4 (CORS FIX)

CHANGES FROM v6.1.3:
- ✅ Fixed CORS for Vercel frontend using after_request handler
- ✅ Added explicit OPTIONS handler for all API routes
- Previous fixes maintained
"""

import os
import sys
import csv
import re
import joblib
import traceback
import pickle
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Handle relative imports for WSGI compatibility
try:
    from auth import auth_bp
    from middleware import token_required
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from auth import auth_bp
    from middleware import token_required

# ------------------------------------------------------------------
# DOMAIN AGE CHECKER MODULE
# ------------------------------------------------------------------

def get_domain_age(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return 'IP Address (No Domain)'
        try:
            import whois
            domain_info = whois.whois(domain)
            creation_date = None
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
            if creation_date:
                age = datetime.now() - creation_date
                years = age.days // 365
                months = (age.days % 365) // 30
                if years > 0:
                    return f"{years} year" if years == 1 else f"{years} years"
                elif months > 0:
                    return f"{months} month" if months == 1 else f"{months} months"
                else:
                    return "Less than 1 month"
        except ImportError:
            pass
        except Exception:
            pass
        return estimate_domain_age_heuristic(domain)
    except Exception:
        return 'Unknown'


def estimate_domain_age_heuristic(domain):
    old_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
        'apple.com', 'github.com', 'stackoverflow.com', 'reddit.com',
        'wikipedia.org', 'netflix.com', 'ebay.com', 'paypal.com',
        'yahoo.com', 'bing.com', 'cnn.com', 'bbc.com', 'nytimes.com'
    ]
    for old_domain in old_domains:
        if domain == old_domain or domain.endswith('.' + old_domain):
            return '10+ years (trusted)'
    current_year = datetime.now().year
    if str(current_year) in domain or str(current_year - 1) in domain:
        return 'Less than 1 year'
    if len(re.findall(r'\d{3,}', domain)) > 0:
        return 'Unknown'
    if len(domain) > 40:
        return 'Unknown'
    return 'Unknown'

# ------------------------------------------------------------------
# MODULAR SCORING ENGINES
# ------------------------------------------------------------------

class MLScoreModule:
    def __init__(self, model):
        self.model = model

    def compute_score(self, url, features):
        if not self.model:
            return 0.5
        try:
            probabilities = self.model.predict_proba([features])[0]
            return float(probabilities[1])
        except:
            return 0.5


class LexicalScoreModule:
    SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
                       '.work', '.click', '.pw', '.cc', '.su']

    def compute_score(self, url):
        score = 0.0
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        if len(url) > 100:
            score += 0.25
        elif len(url) > 75:
            score += 0.15
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.30
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld) or ('.' + tld.lstrip('.') + '.') in domain:
                score += 0.25
                break
        if '@' in url:
            score += 0.20
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            score += 0.10
        elif subdomain_count > 2:
            score += 0.05
        if domain.count('-') > 3:
            score += 0.10
        elif domain.count('-') > 1:
            score += 0.05
        if len(domain) > 50:
            score += 0.15
        elif len(domain) > 30:
            score += 0.08
        suspicious_words = ['verify', 'secure', 'account', 'update', 'login',
                            'signin', 'confirm', 'banking', 'paypal', 'amazon']
        for word in suspicious_words:
            if word in domain:
                score += 0.10
                break
        return round(min(score, 1.0), 4)


class ReputationScoreModule:
    SAFE_DOMAINS = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'twitter.com',
        'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'github.com',
        'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'netflix.com', 'ebay.com',
        'paypal.com'
    ]

    def compute_score(self, url):
        score = 0.0
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        for safe in self.SAFE_DOMAINS:
            if domain == safe or domain.endswith('.' + safe):
                return 0.0
        if parsed.scheme != 'https':
            score += 0.30
        suspicious_words = ['login', 'verify', 'secure', 'account', 'update',
                            'confirm', 'banking', 'signin']
        for word in suspicious_words:
            if word in domain:
                score += 0.15
                break
        brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
                 'netflix', 'ebay', 'instagram', 'twitter']
        for brand in brands:
            if brand in domain:
                if domain == brand + '.com' or domain.endswith('.' + brand + '.com'):
                    score = 0.0
                    break
                else:
                    score += 0.30
                    break
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 0.35
        if len(domain) > 40:
            score += 0.10
        return round(min(score, 1.0), 4)


class BehaviorScoreModule:
    SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                  'buff.ly', 'is.gd', 'cli.gs', 'short.link']

    def compute_score(self, url):
        score = 0.0
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        for shortener in self.SHORTENERS:
            if shortener in url:
                score += 0.30
                break
        special_chars = sum(1 for c in url if c in '-_.~!*\'();:@&=+$,/?#[]')
        if special_chars > 15:
            score += 0.20
        elif special_chars > 8:
            score += 0.10
        if '%' in url:
            pct_count = url.count('%')
            if pct_count > 5:
                score += 0.20
            elif pct_count > 2:
                score += 0.10
        suspicious_paths = ['login', 'signin', 'verify', 'confirm', 'update',
                            'secure', 'account', 'banking', 'paypal', 'password']
        path_hits = sum(1 for p in suspicious_paths if p in path)
        if path_hits > 0:
            score += min(path_hits * 0.10, 0.25)
        redirect_params = ['redirect', 'return', 'continue', 'next', 'url', 'goto']
        if any(p in query for p in redirect_params):
            score += 0.15
        if '//' in path:
            score += 0.10
        if 'javascript:' in url.lower():
            score += 0.40
        return round(min(score, 1.0), 4)


class NLPScoreModule:
    URGENCY_KEYWORDS = ['urgent', 'immediately', 'expire', 'expires', 'expired',
                       'limited', 'hurry', 'act now', 'deadline', 'suspend',
                       'suspended', 'locked', 'blocked']
    PHISHING_KEYWORDS = ['verify', 'account', 'update', 'confirm', 'login', 'signin',
                        'banking', 'secure', 'unusual', 'click', 'here', 'now',
                        'immediately', 'urgent', 'password', 'credential', 'credit',
                        'card', 'ssn', 'social']

    def compute_score(self, url):
        url_lower = url.lower()
        keyword_count = sum(1 for kw in self.PHISHING_KEYWORDS if kw in url_lower)
        base_score = min(keyword_count * 0.12, 0.60)
        urgency_count = sum(1 for kw in self.URGENCY_KEYWORDS if kw in url_lower)
        urgency_bonus = min(urgency_count * 0.10, 0.25)
        return round(min(base_score + urgency_bonus, 1.0), 4)


class InternalEnsembleEngine:
    WEIGHTS = {
        'ml': 1.00,
        'lexical': 0.00,
        'reputation': 0.00,
        'behavior': 0.00,
        'nlp': 0.00
    }
    PHISHING_THRESHOLD = 0.75
    SUSPICIOUS_THRESHOLD = 0.40

    def __init__(self, ml_module, lexical_module, reputation_module,
                 behavior_module, nlp_module):
        self.ml_module = ml_module
        self.lexical_module = lexical_module
        self.reputation_module = reputation_module
        self.behavior_module = behavior_module
        self.nlp_module = nlp_module

    def analyze(self, url, features):
        ml_score = self.ml_module.compute_score(url, features)
        lexical_score = self.lexical_module.compute_score(url)
        reputation_score = self.reputation_module.compute_score(url)
        behavior_score = self.behavior_module.compute_score(url)
        nlp_score = self.nlp_module.compute_score(url)
        final_score = ml_score
        if final_score >= self.PHISHING_THRESHOLD:
            classification = "Phishing"
        elif final_score >= self.SUSPICIOUS_THRESHOLD:
            classification = "Suspicious"
        else:
            classification = "Legitimate"
        return {
            'url': url,
            'classification': classification,
            'ensemble_score': round(final_score, 4),
            'confidence': round(final_score * 100, 2),
            'modules': {
                'ml': round(ml_score, 4),
                'lexical': round(lexical_score, 4),
                'reputation': round(reputation_score, 4),
                'behavior': round(behavior_score, 4),
                'nlp': round(nlp_score, 4)
            },
            'ensemble_weights': self.WEIGHTS,
            'scoring_policy': 'final_score=ml_score (other modules analytical only)'
        }

# ------------------------------------------------------------------
# INLINE FEATURE EXTRACTION
# ------------------------------------------------------------------

def extract_features_inline(url):
    parsed = urlparse(url)
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('_'),
        url.count('?'),
        url.count('='),
        url.count('&'),
        1 if parsed.scheme == 'https' else 0,
        len(parsed.netloc),
        len(parsed.path)
    ]

def explain_features_inline(url):
    parsed = urlparse(url)
    return {
        "domain_age": "Unknown",
        "https": parsed.scheme == 'https',
        "url_length": len(url),
        "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        "suspicious_keywords": any(
            kw in url.lower() for kw in ['verify', 'account', 'login', 'secure', 'update', 'confirm']
        )
    }

try:
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
    if PROJECT_ROOT not in sys.path:
        sys.path.append(PROJECT_ROOT)
    from ai.features import extract_features, explain_features
    print("[✓] ai.features module loaded")
except ImportError:
    extract_features = extract_features_inline
    explain_features = explain_features_inline
    print("[!] ai.features not found — using inline feature extraction")

# ------------------------------------------------------------------
# OPTIONAL IMPORTS
# ------------------------------------------------------------------

try:
    from config import Config
    print("[✓] Config module loaded")
except ImportError:
    class Config:
        CORS_ORIGINS = ['*']
        RATELIMIT_DEFAULT = "100 per minute"
        RATELIMIT_STORAGE_URL = "memory://"
        SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-secret-key')
        JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'phishguard-jwt-secret')
        JWT_EXPIRATION_DELTA = None
        JWT_ALGORITHM = 'HS256'
        MIN_PASSWORD_LENGTH = 8
        REQUIRE_UPPERCASE = True
        REQUIRE_NUMBER = True
        REQUIRE_SPECIAL_CHAR = True
    print("[!] config.py not found — using default Config")

try:
    from database import init_db, ScanHistory
    DATABASE_ENABLED = True
    print("[✓] Database module loaded")
except ImportError:
    DATABASE_ENABLED = False
    init_db = lambda: None
    ScanHistory = None
    print("[!] database.py not found — database features disabled")

AUTH_ENABLED = True

try:
    from services.url_validator import URLValidator
    from services.ensemble_engine import EnsembleDetectionEngine
    from services.lexical_analyzer import URLLexicalAnalyzer
    from services.domain_reputation import DomainReputationChecker
    from services.html_behavior_analyzer import HTMLBehaviorAnalyzer
    from services.nlp_analyzer import NLPPhishingAnalyzer

    url_validator_svc = URLValidator(timeout=5)
    _lexical_svc = URLLexicalAnalyzer()
    _reputation_svc = DomainReputationChecker()
    _behavior_svc = HTMLBehaviorAnalyzer()
    _nlp_svc = NLPPhishingAnalyzer()
    external_ensemble = EnsembleDetectionEngine(
        lexical_analyzer=_lexical_svc,
        reputation_checker=_reputation_svc,
        behavior_analyzer=_behavior_svc,
        nlp_analyzer=_nlp_svc
    )
    ENSEMBLE_ENABLED = True
    print("[✓] External ensemble detection services loaded")
except Exception as _ext_err:
    print(f"[!] External ensemble services not available: {_ext_err}")
    url_validator_svc = None
    external_ensemble = None
    ENSEMBLE_ENABLED = False

# ------------------------------------------------------------------
# APP INITIALIZATION
# ------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY if hasattr(Config, 'SECRET_KEY') else 'phishguard-secret-key'

# ✅ CORS FIX v6.1.4 — after_request handler is the most reliable method
# It manually injects CORS headers for every response including preflight OPTIONS

ALLOWED_ORIGINS = [
    'https://phish-guard-ai-lac.vercel.app',
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:5500',
    'http://127.0.0.1:3000',
    'chrome-extension://',
]

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '')
    # Allow exact match OR any vercel.app subdomain OR any Chrome extension
    if (origin in ALLOWED_ORIGINS or 
        (origin.endswith('.vercel.app') and origin.startswith('https://')) or
        origin.startswith('chrome-extension://')):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
    return response

# Keep flask-cors as backup
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS + ["https://*.vercel.app"]}},
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
     supports_credentials=True)

# Rate limiting
rate_limit_default = getattr(Config, 'RATELIMIT_DEFAULT', "100 per minute")
rate_limit_storage = getattr(Config, 'RATELIMIT_STORAGE_URL', "memory://")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[rate_limit_default],
    storage_uri=rate_limit_storage
)

if AUTH_ENABLED and auth_bp:
    app.register_blueprint(auth_bp, url_prefix='/auth')

if DATABASE_ENABLED:
    with app.app_context():
        init_db()

# ------------------------------------------------------------------
# MODEL LOADING
# ------------------------------------------------------------------

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "model", "phishing_model.pkl")
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "scan_history.csv")

try:
    model = joblib.load(MODEL_PATH)
    print("[✓] ML model loaded successfully with joblib")
except Exception as _e1:
    try:
        with open(MODEL_PATH, 'rb') as _f:
            model = pickle.load(_f)
        print("[✓] ML model loaded successfully with pickle")
    except Exception as _e2:
        print(f"[✗] Failed to load model: {_e1} / {_e2}")
        model = None

# ------------------------------------------------------------------
# INTERNAL ENSEMBLE ENGINE
# ------------------------------------------------------------------

_ml_module = MLScoreModule(model)
_lexical_module = LexicalScoreModule()
_reputation_module = ReputationScoreModule()
_behavior_module = BehaviorScoreModule()
_nlp_module = NLPScoreModule()

internal_ensemble = InternalEnsembleEngine(
    ml_module=_ml_module,
    lexical_module=_lexical_module,
    reputation_module=_reputation_module,
    behavior_module=_behavior_module,
    nlp_module=_nlp_module
)

PHISHING_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.40

# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------

def classify_by_confidence(confidence: float):
    if confidence >= PHISHING_THRESHOLD:
        return "Phishing", "High"
    elif confidence >= SUSPICIOUS_THRESHOLD:
        return "Suspicious", "Medium"
    else:
        return "Legitimate", "Low"

def log_scan(url, label, confidence, risk="Unknown"):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        file_exists = os.path.exists(LOG_PATH)
        with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "url", "label", "confidence", "risk_level"])
            writer.writerow([
                datetime.utcnow().isoformat(),
                url,
                label,
                round(confidence * 100, 2) if confidence <= 1.0 else round(confidence, 2),
                risk
            ])
    except Exception:
        pass  # Don't let logging failures crash the app

def get_model_name():
    if model is None:
        return "No Model (Heuristic)"
    try:
        if hasattr(model, '__class__'):
            return model.__class__.__name__
    except:
        pass
    return "Unknown Model"

def predict_url(url):
    OWN_DOMAINS = [
        'phish-guard-ai-lac.vercel.app',
        'phishguardai-nnez.onrender.com',
    ]
    try:
        features = extract_features(url)
        result = internal_ensemble.analyze(url, features)
        domain_age = get_domain_age(url)
        if model:
            prediction = model.predict([features])[0]
            probabilities = model.predict_proba([features])[0]
            phishing_probability = float(probabilities[1])
            label, risk_level = classify_by_confidence(phishing_probability)
        else:
            phishing_probability = 0.0
            label = 'Unknown'
            risk_level = 'unknown'
        response = {
            'url': url,
            'prediction': label,
            'classification': label,
            'confidence': phishing_probability * 100,
            'risk_level': risk_level.lower(),
            'riskLevel': risk_level,
            'model': get_model_name(),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'modules': {
                'ml': result['modules']['ml'] * 100,
                'lexical': result['modules']['lexical'] * 100,
                'reputation': result['modules']['reputation'] * 100,
                'behavior': result['modules']['behavior'] * 100,
                'nlp': result['modules']['nlp'] * 100
            },
            'module_scores': {
                'ML_model': result['modules']['ml'] * 100,
                'lexical': result['modules']['lexical'] * 100,
                'reputation': result['modules']['reputation'] * 100,
                'behavior': result['modules']['behavior'] * 100,
                'NLP': result['modules']['nlp'] * 100
            },
            'ensemble_contributions': {
                'ml': result['modules']['ml'] * 60,
                'lexical': result['modules']['lexical'] * 15,
                'reputation': result['modules']['reputation'] * 15,
                'behavior': result['modules']['behavior'] * 5,
                'nlp': result['modules']['nlp'] * 5
            },
            'module_contributions': {
                'ML_model': result['modules']['ml'] * 60,
                'lexical': result['modules']['lexical'] * 15,
                'reputation': result['modules']['reputation'] * 15,
                'behavior': result['modules']['behavior'] * 5,
                'NLP': result['modules']['nlp'] * 5
            },
            'metrics': {
                'https': url.startswith('https://'),
                'urlLength': len(url),
                'url_length': len(url),
                'domainAge': domain_age,
                'domain_age': domain_age,
                'features': {
                    'url_length': len(url),
                    'has_https': 1 if url.startswith('https://') else 0,
                    'has_ip': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc) else 0,
                    'num_dots': urlparse(url).netloc.count('.'),
                    'num_hyphens': urlparse(url).netloc.count('-'),
                    'subdomain_count': urlparse(url).netloc.count('.'),
                }
            }
        }
        return response
    except Exception as e:
        traceback.print_exc()
        return None

def extract_metrics_for_extension(url, risk_factors):
    parsed = urlparse(url)
    domain_age = get_domain_age(url)
    if isinstance(risk_factors, dict):
        domain_age = risk_factors.get("domain_age", domain_age)
        suspicious_keywords = risk_factors.get("suspicious_keywords", False)
    else:
        suspicious_keywords = False
    return {
        "domain_age": domain_age,
        "https": parsed.scheme == "https",
        "url_length": len(url),
        "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        "suspicious_keywords": suspicious_keywords
    }

def _build_modules_from_external(ensemble_result):
    if 'modules' in ensemble_result:
        return ensemble_result['modules']
    em = ensemble_result.get('ensemble_modules', {})
    return {
        'ml': em.get('ml_model', {}).get('score', 0.0),
        'lexical': em.get('lexical', {}).get('score', 0.0),
        'reputation': em.get('reputation', {}).get('score', 0.0),
        'behavior': em.get('behavior', {}).get('score', 0.0),
        'nlp': em.get('nlp', {}).get('score', 0.0)
    }

# ------------------------------------------------------------------
# ✅ GLOBAL OPTIONS HANDLER — handles preflight for ALL routes
# ------------------------------------------------------------------

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        return response

# ------------------------------------------------------------------
# ROUTES — HEALTH CHECK
# ------------------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard AI API",
        "version": "6.1.4",
        "model_loaded": model is not None,
        "modules": {
            "ml": "active",
            "lexical": "active",
            "reputation": "active",
            "behavior": "active",
            "nlp": "active"
        },
        "ensemble_weights": internal_ensemble.WEIGHTS,
        "features": {
            "ensemble_detection": True,
            "external_ensemble": ENSEMBLE_ENABLED,
            "url_validation": url_validator_svc is not None,
            "ml_model": model is not None,
            "authentication": AUTH_ENABLED,
            "database": DATABASE_ENABLED,
            "rate_limiting": True
        },
        "timestamp": datetime.now().isoformat()
    }), 200

# ------------------------------------------------------------------
# ROUTES — ENHANCED SCAN
# ------------------------------------------------------------------

@app.route('/api/scan-enhanced', methods=['POST', 'OPTIONS'])
@limiter.limit("30 per minute")
def scan_enhanced():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    if url_validator_svc:
        validation_result = url_validator_svc.validate(url)
        if not validation_result['is_valid']:
            return jsonify({
                "error": "URL_VALIDATION_FAILED",
                "message": validation_result['error'],
                "suggestion": validation_result['suggestion'],
                "validation_details": validation_result['validation_stages'],
                "can_retry": validation_result.get('can_retry', False)
            }), 400

    try:
        features = extract_features(url)
        ml_result = predict_url(url)
        if not ml_result:
            return jsonify({"error": "ML prediction failed"}), 500

        risk_factors = explain_features(url)

        if ENSEMBLE_ENABLED and external_ensemble:
            ensemble_result = external_ensemble.analyze(
                url=url,
                ml_confidence=ml_result['confidence'] / 100,
                ml_prediction=ml_result['prediction'],
                risk_factors=[]
            )
            classification = ensemble_result.get('final_classification', 'Unknown')
            confidence_pct = ensemble_result.get('confidence_percentage', ml_result['confidence'])
            risk_level = ensemble_result.get('final_risk_level', 'Unknown')
            ensemble_score = ensemble_result['ensemble_score']
            detection_modules = ensemble_result.get('ensemble_modules', {})
            detection_breakdown = ensemble_result.get('detection_breakdown', {})
            ensemble_weights = internal_ensemble.WEIGHTS
            modules_flat = _build_modules_from_external(ensemble_result)
        else:
            internal_result = internal_ensemble.analyze(url, features)
            classification = internal_result['classification']
            confidence_pct = internal_result['confidence']
            risk_level = ("High" if classification == "Phishing"
                         else "Medium" if classification == "Suspicious" else "Low")
            ensemble_score = internal_result['ensemble_score']
            detection_modules = internal_result['modules']
            detection_breakdown = internal_result['modules']
            ensemble_weights = internal_result['ensemble_weights']
            modules_flat = internal_result['modules']

        log_scan(url=url, label=classification, confidence=ensemble_score, risk=risk_level)

        return jsonify({
            "url": url,
            "classification": classification,
            "confidence": confidence_pct,
            "risk_level": risk_level,
            "ensemble_score": ensemble_score,
            "detection_method": "ensemble",
            "model": get_model_name(),
            "timestamp": datetime.now().isoformat(),
            "ensemble_weights": ensemble_weights,
            "ml_prediction": {
                "classification": ml_result['prediction'],
                "confidence": ml_result['confidence'],
                "risk_factors": risk_factors
            },
            "modules": modules_flat,
            "ensemble_modules": detection_modules,
            "detection_breakdown": detection_breakdown,
            "metrics": extract_metrics_for_extension(url, risk_factors)
        }), 200

    except Exception as e:
        print("=" * 60)
        print("ERROR IN /api/scan-enhanced:")
        print(traceback.format_exc())
        print("=" * 60)
        return jsonify({"error": "Enhanced scan failed", "details": str(e)}), 500

# ------------------------------------------------------------------
# ROUTES — PUBLIC SCAN
# ------------------------------------------------------------------

@app.route("/api/scan", methods=["POST", "OPTIONS"])
@limiter.limit("30 per minute")
def api_scan():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        result = predict_url(url)
        if result is None:
            return jsonify({"error": "Failed to analyze URL"}), 500

        try:
            risk_factors = explain_features(url)
        except Exception as e:
            print(f"Warning: explain_features failed: {e}")
            risk_factors = {}

        metrics = extract_metrics_for_extension(url, risk_factors)
        log_scan(url=url, label=result['classification'],
                confidence=result['confidence'] / 100,
                risk=result['risk_level'])

        return jsonify({
            "url": url,
            "classification": result['classification'],
            "ensemble_score": result['confidence'] / 100,
            "confidence": result['confidence'],
            "model": get_model_name(),
            "modules": result['modules'],
            "ensemble_weights": internal_ensemble.WEIGHTS,
            "metrics": metrics,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Failed to analyze URL", "details": str(e)}), 500

@app.route("/check_url", methods=["POST", "OPTIONS"])
@limiter.limit("30 per minute")
def check_url():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field missing."}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        result = predict_url(url)
        if result is None:
            return jsonify({"error": "Failed to analyze URL"}), 500

        try:
            risk_factors = explain_features(url)
        except Exception as e:
            print(f"Warning: explain_features failed: {e}")
            risk_factors = {}

        log_scan(url=url, label=result['classification'],
                confidence=result['confidence'] / 100,
                risk=result['risk_level'])

        return jsonify({
            "url": url,
            "label": result['classification'].upper(),
            "phishing_probability": result['confidence'],
            "ensemble_score": result['confidence'] / 100,
            "risk_level": result['risk_level'],
            "risk_factors": risk_factors,
            "modules": result['modules'],
            "ensemble_weights": internal_ensemble.WEIGHTS,
            "model": get_model_name(),
            "timestamp": datetime.now().isoformat(),
            "url_length": len(url)
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Failed to analyze URL", "details": str(e)}), 500

@app.route('/api/predict', methods=['POST', 'OPTIONS'])
@limiter.limit("30 per minute")
def api_predict():
    if request.method == "OPTIONS":
        return "", 200

    try:
        data = request.get_json(silent=True)
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()
        if not url or not url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400

        result = predict_url(url)
        if result is None:
            return jsonify({'error': 'Prediction failed'}), 500

        log_scan(result['url'], result['prediction'],
                result['confidence'] / 100, result['risk_level'])

        return jsonify(result), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Prediction failed'}), 500

# ------------------------------------------------------------------
# ROUTES — AUTHENTICATED
# ------------------------------------------------------------------

@app.route('/api/predict-authenticated', methods=['POST', 'OPTIONS'])
@token_required
@limiter.limit("60 per minute")
def predict_authenticated(current_user=None):
    if request.method == "OPTIONS":
        return "", 200

    try:
        data = request.get_json(silent=True)
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()
        if not url or not url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400

        result = predict_url(url)
        if result is None:
            return jsonify({'error': 'Prediction failed'}), 500

        result['saved'] = False
        if DATABASE_ENABLED and ScanHistory and current_user:
            try:
                ScanHistory.add_scan(
                    user_id=current_user['id'],
                    url=result['url'],
                    prediction=result['prediction'],
                    confidence=result['confidence'] / 100,
                    risk_level=result['risk_level']
                )
                result['saved'] = True
            except Exception as db_err:
                print(f"Failed to save scan history: {db_err}")

        log_scan(result['url'], result['prediction'],
                result['confidence'] / 100, result['risk_level'])

        return jsonify(result), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Prediction failed'}), 500

@app.route('/api/history', methods=['GET', 'OPTIONS'])
@token_required
@limiter.limit("20 per minute")
def get_history(current_user=None):
    if request.method == "OPTIONS":
        return "", 200

    if not DATABASE_ENABLED or not ScanHistory:
        return jsonify({'error': 'Database not available'}), 503

    try:
        limit = min(request.args.get('limit', 50, type=int), 100)
        history = ScanHistory.get_user_history(current_user['id'], limit)
        return jsonify({'history': history, 'count': len(history)}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Failed to retrieve history'}), 500

@app.route('/api/stats', methods=['GET', 'OPTIONS'])
@token_required
@limiter.limit("10 per minute")
def get_stats(current_user=None):
    if request.method == "OPTIONS":
        return "", 200

    if not DATABASE_ENABLED or not ScanHistory:
        return jsonify({'error': 'Database not available'}), 503

    try:
        stats = ScanHistory.get_user_stats(current_user['id'])
        return jsonify({'stats': stats}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

# ------------------------------------------------------------------
# AUTH ROUTES OPTIONS (for login/register preflight)
# ------------------------------------------------------------------

@app.route('/auth/login', methods=['OPTIONS'])
@app.route('/auth/register', methods=['OPTIONS'])
@app.route('/auth/validate', methods=['OPTIONS'])
@app.route('/auth/profile', methods=['OPTIONS'])
def auth_options():
    return "", 200

# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded.'}), 429

# ------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PHISHGUARD AI - v6.1.4 (CORS FIX)")
    print("=" * 60)
    print(f"[✓] Model loaded: {model is not None}")
    print(f"[✓] External ensemble: {ENSEMBLE_ENABLED}")
    print(f"[✓] URL validation: {url_validator_svc is not None}")
    print(f"[✓] Database: {DATABASE_ENABLED}")
    print(f"[✓] Auth: {AUTH_ENABLED}")
    print("")
    print("📊 FIXES IN v6.1.4:")
    print("   ✅ CORS fixed with after_request handler")
    print("   ✅ Global OPTIONS preflight handler added")
    print("   ✅ All routes now handle OPTIONS method")
    print("   ✅ Auth routes OPTIONS handlers added")
    print("=" * 60)

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)