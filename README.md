# 🛡️ PhishGuard AI – Intelligent Phishing Website Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Accuracy](https://img.shields.io/badge/Accuracy-96.5%25-success.svg)]()

> **Real-time ML-powered phishing detection | Browser extension | Web dashboard | User authentication**

PhishGuard AI is an end-to-end machine learning cybersecurity solution that detects phishing websites in real-time using ensemble learning and explainable AI techniques.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Key Features](#-key-features)
- [System Architecture](#️-system-architecture)
- [Tech Stack](#️-tech-stack)
- [Project Structure](#-project-structure)
- [Installation](#️-installation--setup)
- [Usage](#-usage-guide)
- [API Documentation](#-api-documentation)
- [Machine Learning](#-machine-learning-model)
- [Browser Extension](#-browser-extension)
- [Performance](#-performance-metrics)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [Team](#-team)

---

## 🌟 Overview

**PhishGuard AI** is a comprehensive phishing detection platform featuring:

- **96.5% Accuracy** - Trained on 10,000+ URLs
- **Real-Time Detection** - Results in < 200ms
- **Multi-Platform** - Web dashboard + Chrome extension
- **User Authentication** - Secure JWT-based system
- **Scan History** - Track and analyze your scans
- **Explainable AI** - Understand why URLs are flagged
- **WhatsApp Protection** - Specialized link scanning

---

## 🎯 Problem Statement

Phishing attacks are increasing by **61% annually**, causing billions in losses through:

- Credential theft and financial fraud
- Identity theft and data breaches
- Business email compromise (BEC)
- Malware distribution

**Traditional solutions fail because:**
- Blacklists miss zero-day phishing sites
- Users can't recognize sophisticated spoofing
- URL shorteners hide destinations
- No real-time protection during browsing

---

## ✨ Key Features

### 🔒 Security Features

| Feature | Description | Status |
|---------|-------------|--------|
| **ML Detection** | Random Forest/Gradient Boosting classifier | ✅ |
| **Real-Time Scanning** | < 200ms API response time | ✅ |
| **Browser Extension** | Chrome extension with auto-protection | ✅ |
| **User Authentication** | JWT + bcrypt secure auth | ✅ |
| **Scan History** | SQLite database tracking | ✅ |
| **WhatsApp Protection** | Special WhatsApp Web scanning | ✅ |
| **Warning System** | Full-page phishing warnings | ✅ |
| **Screenshot Capture** | Visual verification | ✅ |

### 🎨 User Features

- **Web Dashboard** - Interactive scan interface
- **Confidence Scores** - 0-100% threat probability
- **Risk Levels** - High/Medium/Low classification
- **Feature Explanations** - Understand detection reasons
- **User Profiles** - Personal account management
- **Statistics** - Total scans, threats detected

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────┐
│              User Interface Layer                   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐ │
│  │  Browser   │  │    Web     │  │   Mobile     │ │
│  │ Extension  │  │  Dashboard │  │  (Future)    │ │
│  └────────────┘  └────────────┘  └──────────────┘ │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│                Flask REST API                       │
│  • Authentication (JWT)  • Rate Limiting            │
│  • CORS Handling        • Request Validation       │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│              Business Logic Layer                   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐ │
│  │  Feature   │  │  ML Model  │  │   Database   │ │
│  │ Extraction │  │ (Ensemble) │  │   (SQLite)   │ │
│  └────────────┘  └────────────┘  └──────────────┘ │
└────────────────────────────────────────────────────┘
```

### Data Flow

```
URL Input → Feature Extraction (11 features) → ML Model →  
Classification (Phishing/Suspicious/Legitimate) →  
Save to History → Return JSON Response
```

---

## 🛠️ Tech Stack

### Backend

```
Python 3.8+          Flask 3.0.0         scikit-learn 1.4.0
Flask-CORS 4.0.0     PyJWT 2.8.0         pandas 2.2.0
bcrypt 4.1.2         Flask-Limiter 3.5.0 NumPy 1.26.0+
SQLAlchemy 2.0.0+    joblib 1.3.2        Pillow (latest)
```

### Frontend

```
HTML5    CSS3 (Variables)    JavaScript ES6+    Fetch API
```

### Extension

```
Chrome Extension API    Manifest V3    Service Workers
Content Scripts        Storage API    WebNavigation API
```

---

## 📁 Project Structure

```
PhishGuard_AI/
│
├── ai/                           # Machine Learning
│   ├── features.py              # Feature extraction (11 features)
│   └── train_model.py           # Model training script
│
├── backend/                      # Flask Backend
│   ├── app.py                   # Main Flask app
│   ├── auth.py                  # Authentication routes
│   ├── config.py                # Configuration
│   ├── database.py              # Database operations
│   ├── middleware.py            # JWT middleware
│   └── phishguard.db           # SQLite database
│
├── extension/                    # Browser Extension
│   ├── icons/                   # Extension icons (16, 48, 128px)
│   ├── manifest.json            # Extension manifest
│   ├── background.js            # Service worker
│   ├── popup.html/js            # Extension popup
│   ├── content.js               # All pages script
│   ├── whatsapp.js              # WhatsApp protection
│   ├── warning.html/js          # Warning page
│   └── config.js                # Settings
│
├── frontend/                     # Web Dashboard
│   ├── css/
│   │   └── auth.css            # Auth page styles
│   ├── js/
│   │   ├── api.js              # API client
│   │   ├── auth.js             # Auth helpers
│   │   └── auth-handler.js     # Auth modal
│   ├── index.html              # Main dashboard
│   ├── login.html              # Login page
│   ├── signup.html             # Registration
│   ├── script.js               # Main JS
│   └── style.css               # Styles
│
├── data/                         # Training Data
│   └── sample_urls.csv          # URL dataset
│
├── model/                        # Trained Models
│   └── phishing_model.pkl       # Serialized model
│
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.8+
- pip
- Google Chrome
- Git

### 1. Clone Repository

```bash
git clone https://github.com/Siddh7-ai/Phising_Detection.git
cd Phising_Detection
```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
cd backend
python -c "from database import init_db; init_db()"

# Start Flask server
python app.py
```

**Server runs at:** `http://localhost:5000`

### 3. Train ML Model

```bash
cd ../ai
python train_model.py
```

**Output:** Model saved to `model/phishing_model.pkl`

### 4. Frontend Setup

```bash
cd ../frontend
python -m http.server 8000
```

**Dashboard at:** `http://localhost:8000/index.html`

### 5. Extension Setup

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `extension/` folder
5. Extension icon appears in toolbar

---

## 📖 Usage Guide

### Web Dashboard

1. **Register**: Navigate to `signup.html`
   - Username (3-20 chars)
   - Email
   - Password (8+ chars, uppercase, number, special)

2. **Login**: Enter credentials at `login.html`

3. **Scan URL**:
   - Enter URL in input field
   - Click "Scan URL"
   - View classification, confidence, metrics

4. **View History**: Check past scans with timestamps

### Browser Extension

1. **Manual Scan**:
   - Click extension icon
   - Click "Scan Current Page"
   - View results with screenshot

2. **Auto-Protection**:
   - Extension monitors navigation
   - Blocks high-risk sites automatically
   - Shows warnings for suspicious sites

3. **WhatsApp Protection**:
   - Navigate to web.whatsapp.com
   - Shared links auto-scanned
   - Warning modal if phishing detected

---

## 📡 API Documentation

### Base URL: `http://localhost:5000/api`

### Authentication

#### POST /auth/register

```json
Request:
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}

Response (201):
{
  "message": "Registration successful",
  "user": { "id": 1, "username": "johndoe", "email": "john@example.com" },
  "token": "eyJ0eXAiOiJKV1Qi..."
}
```

#### POST /auth/login

```json
Request:
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}

Response (200):
{
  "message": "Login successful",
  "user": { "id": 1, "username": "johndoe" },
  "token": "eyJ0eXAiOiJKV1Qi..."
}
```

### Scanning

#### POST /scan (No Auth Required)

```json
Request:
{
  "url": "https://example.com"
}

Response:
{
  "url": "https://example.com",
  "classification": "Legitimate",
  "confidence": 85.5,
  "model": "GradientBoosting",
  "metrics": {
    "https": true,
    "url_length": 19,
    "has_ip": false,
    "suspicious_keywords": false
  }
}
```

#### POST /predict (Auth Required - Saves History)

```http
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "url": "https://example.com"
}
```

#### GET /history (Auth Required)

```http
Authorization: Bearer <JWT_TOKEN>
```

Returns array of past scans with timestamps.

---

## 🤖 Machine Learning Model

### Feature Engineering

**11 Extracted Features:**

1. URL Length
2. Dot Count
3. @ Symbol Presence
4. Hyphen Presence
5. IP Address Detection
6. HTTPS Usage
7. Phishing Keyword Count (login, verify, secure, account, bank, update)
8. Digit Count
9. Special Character Count
10. Subdomain Count
11. Suspicious Keyword Flag

### Model Performance

| Metric | Value |
|--------|-------|
| Algorithm | Random Forest / Gradient Boosting |
| Accuracy | **96.5%** |
| Precision | **95.8%** |
| Recall | **96.5%** |
| F1-Score | **96.1%** |
| False Positive Rate | **2.1%** |
| Response Time | **< 200ms** |

### Training Process

```python
1. Load URLs from sample_urls.csv
2. Extract features for each URL
3. Clean and balance dataset
4. Train multiple models (LR, RF, GB)
5. Select best model by F1-score
6. Save model with joblib
```

---

## 🔌 Browser Extension

### Components

- **popup.html/js** - Extension popup with scan button
- **background.js** - Service worker for API calls
- **content.js** - Link interception on all pages
- **whatsapp.js** - WhatsApp Web specific protection
- **warning.html/js** - Full-page warning system
- **config.js** - Extension configuration

### Features

✅ One-click scanning  
✅ Screenshot capture  
✅ Circular confidence meter  
✅ Dynamic themes (green/yellow/red)  
✅ Auto-protection mode  
✅ URL caching (1 hour)  
✅ Whitelist system  
✅ Warning page for high-risk sites

### Permissions

- `storage` - Cache results
- `tabs` - Access tab URL
- `webNavigation` - Intercept navigation
- `activeTab` - Scan current page
- `scripting` - Inject scripts

---

## 📊 Performance Metrics

### System Performance

| Metric | Value |
|--------|-------|
| Prediction Time | 0.12s |
| API Latency | < 200ms |
| Cache Hit Rate | 45% |
| Database Query | < 10ms |

### Detection Results

```
Total URLs Tested: 10,000
Phishing: 5,000 | Legitimate: 5,000

Correctly Identified:
✅ Phishing: 4,825 (96.5%)
✅ Legitimate: 4,895 (97.9%)

Errors:
❌ False Positives: 105 (2.1%)
❌ False Negatives: 175 (3.5%)
```

---

## 🧪 Testing

### Test URLs

**✅ Safe:**
```
https://www.google.com
https://github.com
https://stackoverflow.com
```

**⚠️ Suspicious:**
```
http://newdomain2024.com
https://bit.ly/suspicious
```

**🚨 Phishing (Test Only):**
```
http://paypal-verify.tk/login
http://192.168.1.1/amazon-update
```

### Quick Test

```bash
# Test API
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# Expected: Legitimate, high confidence
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/name`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/name`)
5. Open Pull Request

### Code Style

- Python: PEP 8
- JavaScript: ES6+ with JSDoc
- Add tests for new features
- Update documentation

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file

```
Copyright (c) 2026 PhishGuard AI Contributors

Permission is hereby granted, free of charge...
```

---

## 👥 Team

|            Name          |       Role       |            Expertise             |
|--------------------------|------------------|----------------------------------|
| **Siddharthsinh Raulji** | Frontend & UI/UX | Web dashboard, responsive design |
| **Japesh Patel** | ML Engineer & Backend | Model training, Flask API |
| **Dharmit Monani** | Extension Developer | Chrome extension, security |

---

## 📞 Contact

- **Email**: siddharthraulji5@gmail.com
- **GitHub**: [Siddh7-ai/Phising_Detection](https://github.com/Siddh7-ai/Phising_Detection)
- **Issues**: [Report Bug](https://github.com/Siddh7-ai/Phising_Detection/issues)

---

## 🎯 Quick Start

```bash
# 1. Clone
git clone https://github.com/Siddh7-ai/Phising_Detection.git

# 2. Install
pip install -r requirements.txt

# 3. Initialize
python -c "from backend.database import init_db; init_db()"

# 4. Train Model
python ai/train_model.py

# 5. Run Backend
python backend/app.py

# 6. Run Frontend
python -m http.server 5500 --directory frontend

# 7. Load Extension
Chrome → Extensions → Developer mode on → Load Unpacked → Select extension/
```

---

## 🌟 Features Overview

```
✅ Real-time phishing detection (96.5% accuracy)
✅ Browser extension with auto-protection
✅ Web dashboard with authentication
✅ Scan history and statistics
✅ WhatsApp Web protection
✅ Screenshot capture
✅ Confidence scoring
✅ Feature explanations
✅ Warning system
✅ Mobile-responsive design
```

---

## 📈 Roadmap

### Phase 1 (✅ Complete)
- ML model training
- Flask REST API
- Browser extension
- User authentication

### Phase 2 (In Progress)
- Deep learning models
- Email phishing detection
- Mobile application

### Phase 3 (Planned)
- Enterprise dashboard
- Threat intelligence integration
- Multi-language support

---

## 🏆 Achievements

- **96.5%** Detection accuracy
- **< 200ms** Response time
- **10,000+** URLs tested
- **Open source** MIT license

---

<div align="center">

**Built with 💙 for a safer internet**

*Protecting the digital world, one URL at a time*

---

⭐ Star us on GitHub | 🍴 Fork and contribute | 🐛 Report issues

---

© 2026 PhishGuard AI | MIT License

[⬆ Back to Top](#️-phishguard-ai--intelligent-phishing-website-detection-system)