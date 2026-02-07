# 🛡️ PhishGuard AI — Intelligent Phishing Website Detection System

## 📋 Abstract

PhishGuard AI is an end-to-end machine learning-powered cybersecurity solution designed to detect and classify phishing websites in real-time. The system combines advanced feature engineering, ensemble learning algorithms, and Explainable AI (XAI) techniques to provide accurate threat assessments with transparent decision-making. Built with a Flask-based REST API backend and a lightweight browser extension, PhishGuard AI delivers immediate protection against phishing attacks directly within the user's browsing environment.

---

## 🎯 Problem Statement

Phishing attacks remain one of the most prevalent cybersecurity threats, responsible for significant financial losses and data breaches worldwide. Traditional blacklist-based detection methods fail to identify newly created phishing sites, while average users lack the technical expertise to recognize sophisticated spoofing attempts. There is an urgent need for an intelligent, proactive system that can:

- Detect zero-day phishing websites not present in existing databases
- Provide real-time threat assessment during web browsing
- Offer explainable predictions to build user trust
- Differentiate between legitimate, suspicious, and malicious domains

---

## 💡 Motivation & Importance

### Why This Matters

- **Rising Threat Landscape**: Phishing attacks increased by 61% in recent years, targeting individuals and organizations alike
- **Human Vulnerability**: Social engineering exploits human psychology, making technical defenses essential
- **Financial Impact**: Billions in losses annually from credential theft and financial fraud
- **Privacy Concerns**: Stolen personal data leads to identity theft and long-term consequences

### Our Contribution

This project demonstrates how machine learning can augment traditional security measures, providing an intelligent first line of defense that learns from patterns rather than relying solely on known threat databases.

---

## 🚀 Solution Overview

PhishGuard AI implements a three-tier risk classification system powered by machine learning:

- **Backend**: Flask-based REST API serving ML model predictions
- **ML Engine**: Ensemble classifier trained on URL-based and domain-based features
- **Frontend Interface**: Web application for manual URL verification
- **Browser Extension**: Chrome/Firefox extension for real-time scanning
- **Explainability Layer**: SHAP (SHapley Additive exPlanations) for transparent predictions

---

## 🏗️ System Architecture

```
User Input (URL)
    ↓
Browser Extension / Web Interface
    ↓
Flask REST API
    ↓
Feature Extraction Module
    ↓
Trained ML Model (Random Forest / XGBoost)
    ↓
Risk Classification (Phishing / Suspicious / Legitimate)
    ↓
SHAP Explainability Layer
    ↓
JSON Response with Prediction + Explanation
    ↓
Display to User (Alert / Dashboard)
```

---

## 🤖 Machine Learning Approach

### Feature Engineering

The system extracts **30+ discriminative features** from URLs without requiring page content analysis:

**URL-Based Features:**
- Domain length, subdomain count, presence of IP address
- Special character frequency (-, @, //, etc.)
- HTTPS usage and certificate validity
- URL shortening service detection
- Path depth and query parameter analysis

**Domain-Based Features:**
- Domain age and registration length
- WHOIS information availability
- DNS record consistency
- Domain reputation scores
- TLD (Top-Level Domain) analysis

**Lexical Features:**
- Entropy calculation
- Brand name impersonation detection
- Suspicious keyword presence

### Model Selection

Multiple algorithms were evaluated during development:

| Algorithm | Accuracy | Precision | Recall | F1-Score |
|-----------|----------|-----------|--------|----------|
| Random Forest | 96.2% | 95.8% | 96.5% | 96.1% |
| XGBoost | 97.1% | 96.9% | 97.3% | 97.1% |
| SVM | 93.5% | 92.8% | 94.1% | 93.4% |
| Logistic Regression | 89.7% | 88.5% | 90.2% | 89.3% |

**Final Model**: XGBoost ensemble classifier selected for optimal performance.

### Evaluation Metrics

- **Accuracy**: Overall correctness of predictions
- **Precision**: Minimizing false positives (legitimate sites marked as phishing)
- **Recall**: Minimizing false negatives (phishing sites marked as legitimate)
- **F1-Score**: Harmonic mean balancing precision and recall
- **ROC-AUC**: Model's ability to distinguish between classes

---

## 🚦 Classification Categories

### 🔴 Phishing (High Risk)

**Characteristics:**
- Strong indicators of malicious intent
- Confidence score > 70%
- Multiple red flags detected

**Example URLs:**
```
http://paypal-verify-account.tk/login
https://secure-banking-update.ml/signin
http://192.168.1.1/amazon-login
```

**User Action**: Block access immediately with warning

---

### 🟡 Suspicious (Medium Risk)

**Characteristics:**
- Mixed signals or inconclusive evidence
- Confidence score between 40-70%
- Requires user discretion

**Example URLs:**
```
https://offer-limited-time.com/claim
http://app-update-required.net
https://short.ly/xyz123
```

**User Action**: Proceed with extreme caution

---

### 🟢 Legitimate (Low Risk)

**Characteristics:**
- Established domain with clean history
- Confidence score > 70% for legitimacy
- Valid SSL certificate and proper registration

**Example URLs:**
```
https://www.google.com
https://github.com/username/repo
https://www.amazon.com/products
```

**User Action**: Safe to proceed

---

## 🔍 Explainable AI (XAI)

### Why Explainability Matters

Machine learning models often function as "black boxes," making decisions without transparency. In cybersecurity, users need to understand **why** a URL was flagged to:

- Build trust in the system
- Learn to recognize phishing patterns
- Validate model decisions
- Enable security teams to investigate further

### SHAP Implementation

PhishGuard AI integrates **SHAP (SHapley Additive exPlanations)** to decompose each prediction:

**Output Includes:**
- Top 5 contributing features for the decision
- Positive/negative impact on final classification
- Feature importance visualization

**Example Explanation:**
```
URL: http://paypal-secure-login.tk

Prediction: PHISHING (Confidence: 94%)

Top Contributing Features:
1. Suspicious TLD (.tk) → +0.42 (High Risk)
2. Domain age < 30 days → +0.38 (High Risk)
3. Brand name in subdomain → +0.31 (High Risk)
4. No HTTPS → +0.27 (High Risk)
5. Abnormal URL length → +0.18 (Medium Risk)
```

---

## 🌐 Backend API Design

### Endpoint

```
POST /api/predict
```

### Request Format

```json
{
  "url": "https://example-suspicious-site.com/login"
}
```

### Response Format

```json
{
  "url": "https://example-suspicious-site.com/login",
  "prediction": "Suspicious",
  "confidence": 0.68,
  "risk_level": "medium",
  "explanation": {
    "top_features": [
      {
        "feature": "domain_age",
        "value": "45 days",
        "impact": 0.23,
        "description": "Relatively new domain"
      },
      {
        "feature": "https_present",
        "value": true,
        "impact": -0.15,
        "description": "Valid SSL certificate detected"
      }
    ]
  },
  "timestamp": "2024-02-07T10:30:45Z"
}
```

---

## 🔌 Browser Extension Workflow

### Installation
1. Load unpacked extension in Chrome/Firefox developer mode
2. Grant necessary permissions (activeTab, webRequest)
3. Extension icon appears in toolbar

### Real-Time Protection
1. User navigates to any URL
2. Extension captures URL before page load
3. Sends POST request to Flask API
4. Receives prediction within milliseconds
5. Displays color-coded badge:
   - 🔴 Red: Phishing detected (blocks access)
   - 🟡 Yellow: Suspicious (shows warning)
   - 🟢 Green: Legitimate (allows access)

### User Controls
- Whitelist trusted domains
- View detailed SHAP explanations
- Report false positives/negatives
- Toggle protection on/off

---

## 📁 Project Structure

```
PhishGuard-AI/
│
├── backend/
│   ├── app.py                 # Flask application
│   ├── model.py               # ML model loading and prediction
│   ├── feature_extractor.py   # URL feature extraction
│   ├── requirements.txt       # Python dependencies
│   └── models/
│       └── phishguard_model.pkl
│
├── extension/
│   ├── manifest.json          # Extension configuration
│   ├── background.js          # Background script
│   ├── popup.html             # Extension popup UI
│   ├── popup.js               # Popup logic
│   └── content.js             # Content script
│
├── frontend/
│   ├── index.html             # Web interface
│   ├── styles.css             # Styling
│   └── script.js              # Frontend logic
│
├── notebooks/
│   ├── data_preprocessing.ipynb
│   ├── model_training.ipynb
│   └── evaluation.ipynb
│
├── dataset/
│   └── phishing_dataset.csv
│
├── README.md
└── LICENSE
```

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.8+
- pip package manager
- Chrome/Firefox browser (for extension)
- Git

### Backend Setup

```bash
# Clone repository
git clone https://github.com/Siddh7-ai/Phising_Detection.git
cd phishguard-ai/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run Flask server
python app.py
```

The API will be available at `http://localhost:5000`

### Browser Extension Setup

**Chrome:**
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension/` folder

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` from `extension/` folder

### Frontend Setup

```bash
cd frontend
# Simply open index.html in browser
# Or serve with a local server:
python -m http.server 8080
```

---

## 📖 How to Use

### Web Application

1. Navigate to `http://localhost:8080` (or open `index.html`)
2. Enter URL in the input field
3. Click "Analyze URL"
4. View prediction with confidence score
5. Expand "Explanation" section for SHAP analysis
6. Check feature contributions

### Browser Extension

1. Browse normally with extension installed
2. Extension automatically scans each URL
3. Badge color indicates risk level:
   - Green = Safe
   - Yellow = Caution advised
   - Red = Blocked with alert
4. Click extension icon for detailed report
5. Override protection if false positive detected

---

## 📊 Results & Observations

### Model Performance

- **Training Accuracy**: 97.1%
- **Validation Accuracy**: 96.8%
- **Test Accuracy**: 96.5%
- **False Positive Rate**: 2.1%
- **False Negative Rate**: 3.4%

### Key Findings

1. **Most Discriminative Features**:
   - Domain age (23% importance)
   - HTTPS presence (18% importance)
   - URL length (15% importance)
   - Special character count (12% importance)

2. **Common Phishing Patterns**:
   - Use of free TLDs (.tk, .ml, .ga)
   - IP addresses instead of domain names
   - Excessive hyphens in domain
   - Subdomain impersonation of brands

3. **Performance Metrics**:
   - Average prediction time: 0.12 seconds
   - API response latency: < 200ms
   - Extension overhead: Negligible

---

## ⚠️ Limitations

### Current Constraints

1. **Feature-Based Detection**: Relies on extractable URL/domain features; cannot analyze page content or JavaScript behavior
2. **Zero-Day Sophistication**: Highly sophisticated phishing sites mimicking all legitimate patterns may evade detection
3. **Domain Privacy**: WHOIS-protected domains reduce feature availability
4. **Language Support**: Brand impersonation detection optimized for English
5. **Offline Functionality**: Requires internet connection for API calls

### Known Edge Cases

- Newly registered legitimate domains may be flagged as suspicious
- URL shorteners reduce feature extraction accuracy
- Internationalized domain names (IDNs) require additional processing

---

## 🔮 Future Enhancements

### Short-Term Goals

- [ ] Implement caching layer for frequently checked URLs
- [ ] Add support for bulk URL scanning
- [ ] Develop mobile application (Android/iOS)
- [ ] Integrate with popular password managers

### Medium-Term Goals

- [ ] Incorporate NLP for page content analysis
- [ ] Deploy deep learning models (CNN/LSTM) for pattern recognition
- [ ] Build community-driven feedback loop for model improvement
- [ ] Add support for email phishing link detection

### Long-Term Vision

- [ ] Real-time threat intelligence integration
- [ ] Federated learning for privacy-preserving model updates
- [ ] Cross-platform SDK for third-party integration
- [ ] Enterprise-grade dashboard with analytics
- [ ] Automated takedown request generation for confirmed phishing sites

---

## 💼 Use Cases

### Individual Users
- Personal browsing protection
- Safe online shopping and banking
- Protection for elderly/less tech-savvy family members

### Educational Institutions
- Student awareness training
- Safe research environment
- Cybersecurity lab demonstrations

### Small & Medium Businesses
- Employee endpoint protection
- Reduced risk of credential theft
- Compliance support

### Security Researchers
- Phishing campaign analysis
- Feature importance research
- Threat intelligence gathering

---

## 🎓 Conclusion

PhishGuard AI demonstrates the practical application of machine learning in cybersecurity, addressing a real-world threat through intelligent automation. By combining robust feature engineering, ensemble learning, and explainable AI, the system achieves high accuracy while maintaining transparency—a critical requirement in security applications.

The modular architecture allows for continuous improvement through model retraining, feature expansion, and integration with emerging threat intelligence sources. As phishing techniques evolve, PhishGuard AI's adaptive learning approach ensures sustained effectiveness.

This project serves as both a functional security tool and an educational resource, showcasing how data science can empower individuals and organizations to defend against cyber threats proactively.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 PhishGuard AI Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

**Built with 💙 for a safer internet**

**Contributors**: Siddharthsinh Raulji | Japesh Patel | Dharmit Monani

**Contact**: siddharthraulji5@gmail.com 

**Repository**: https://github.com/Siddh7-ai/Phising_Detection.git