# === backend/app.py ===
"""
app.py
-------
Flask REST API for Phishing Website Detection System.

Responsibilities:
- Load trained ML model once at startup
- Accept URL via POST /check_url
- Extract features
- Perform prediction
- Return explainable, judge-friendly JSON response

Tech:
- Flask
- Scikit-learn (inference only)
- Security-first defaults
"""

import os
import sys
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

# ------------------------------------------------------------------
# PATH FIX (CRITICAL)
# ------------------------------------------------------------------

# Absolute path to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Ensure project root is in PYTHONPATH
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# ------------------------------------------------------------------
# IMPORTS (after path fix)
# ------------------------------------------------------------------
from ai.features import extract_features, explain_features

# ------------------------------------------------------------------
# APP INITIALIZATION
# ------------------------------------------------------------------
app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------
# LOAD TRAINED MODEL
# ------------------------------------------------------------------
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")

try:
    model = joblib.load(MODEL_PATH)
    print("[✓] ML model loaded successfully")
except Exception as e:
    print("[✗] Failed to load model:", e)
    model = None

# ------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------
def classify_output(prediction: int, confidence: float) -> str:
    """
    Convert numeric prediction to human-readable label.
    Conservative logic for security systems.
    """
    if prediction == 1 and confidence >= 0.8:
        return "PHISHING"
    if prediction == 1 or confidence < 0.7:
        return "SUSPICIOUS"
    return "SAFE"


def determine_risk(label: str, confidence: float) -> str:
    """
    Determine risk level for end users.
    """
    if label == "PHISHING":
        return "High"
    if label == "SUSPICIOUS":
        return "Medium"
    return "Low"

# ------------------------------------------------------------------
# ROUTES
# ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "running",
        "message": "Phishing Detection API is live"
    })


@app.route("/check_url", methods=["POST"])
def check_url():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field missing."}), 400

    url = data["url"].strip()

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        # Feature extraction
        features = extract_features(url)

        # Prediction
        probabilities = model.predict_proba([features])[0]
        phishing_confidence = float(probabilities[1])
        prediction = int(phishing_confidence >= 0.5)

        # Classification
        label = classify_output(prediction, phishing_confidence)
        risk_level = determine_risk(label, phishing_confidence)

        # Explainability
        risk_factors = explain_features(url)

        return jsonify({
            "url": url,
            "label": label,
            "confidence": round(phishing_confidence, 3),
            "risk_level": risk_level,
            "risk_factors": risk_factors
        }), 200

    except Exception as e:
        return jsonify({
            "error": "Failed to analyze URL",
            "details": str(e)
        }), 500

# ------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
