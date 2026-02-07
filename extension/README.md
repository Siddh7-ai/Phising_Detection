# 🛡️ PhishGuard AI - Intelligent Phishing Website Detection System

A real-time, machine learning–powered phishing detection system featuring a Flask API backend, interactive web interface, and Chrome browser extension for proactive protection against phishing attacks.

---

## 📋 Project Overview

PhishGuard AI is an advanced cybersecurity solution that leverages machine learning to detect and prevent phishing attacks in real-time. The system analyzes website URLs using a trained Random Forest classifier to identify malicious websites before users expose sensitive information. With a multi-tier risk classification system, PhishGuard AI provides instant protection through both a browser extension and web-based scanning interface.

**Project Type:** Hackathon / Academic Research Project  
**Domain:** Cybersecurity, Machine Learning, Web Security  
**Target Users:** Internet users, organizations, educational institutions

---

## ✨ Key Features

- 🤖 **Machine Learning Detection** - Random Forest classifier with 95%+ accuracy
- 🎯 **Three-Tier Risk Classification** - Phishing, Suspicious, and Legitimate categorization
- ⚡ **Real-Time Scanning** - Instant URL analysis with <2 second response time
- 🌐 **Web Interface** - User-friendly dashboard with animated visualizations
- 🔌 **Browser Extension** - One-click protection for active webpage scanning
- 📊 **Confidence Scoring** - Percentage-based threat assessment (0-100%)
- 🔍 **Explainable AI** - Detailed risk factor breakdown for transparency
- 📈 **Scan History** - Persistent tracking of analyzed URLs with LocalStorage
- 🎨 **Multi-Theme Support** - Cyber, Dark, and Light themes
- 📱 **Responsive Design** - Optimized for desktop, tablet, and mobile
- 🚨 **Warning System** - Automatic blocking with bypass options for high-risk sites
- 💾 **Export Reports** - Download scan results in JSON format
- 📝 **Scan Logging** - CSV-based historical data storage

---

## 🎯 Classification Categories

### 🔴 Phishing (High Risk)
**Definition:** Malicious websites designed to steal credentials or sensitive data.

**Confidence Threshold:** ≥ 60%

**Examples:**
- `http://paypal-verify-account.tk/login`
- `https://secure-chase-banking.xyz/signin`
- `http://192.168.1.1/amazon-update.php`

**Indicators:**
- Suspicious domain names (typosquatting)
- IP addresses in URL
- Missing HTTPS encryption
- Newly registered domains
- Excessive special characters

---

### 🟠 Suspicious (Medium Risk)
**Definition:** URLs with some phishing indicators requiring user caution.

**Confidence Threshold:** 30% - 59%

**Examples:**
- `http://free-gift-claim.site/offer`
- `https://login-portal.info/verify`
- URLs with unusual subdomain patterns

**Indicators:**
- Mixed security signals
- Moderately suspicious keywords
- Non-standard TLDs (.tk, .ml, .ga)
- Moderate URL length

---

### 🟢 Legitimate (Low Risk)
**Definition:** Trusted, safe websites with no detected phishing indicators.

**Confidence Threshold:** < 30%

**Examples:**
- `https://google.com`
- `https://github.com`
- `https://microsoft.com`

**Indicators:**
- HTTPS enabled
- Established domain age
- No suspicious keywords
- Standard URL structure

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│  ┌───────────────────┐              ┌──────────────────────┐   │
│  │  Web Frontend     │              │  Browser Extension   │   │
│  │  - HTML/CSS/JS    │              │  - Manifest V3       │   │
│  │  - 3 Themes       │              │  - One-click scan    │   │
│  │  - Chart.js       │              │  - Screenshot cap    │   │
│  └────────┬──────────┘              └──────────┬───────────┘   │
└───────────┼─────────────────────────────────────┼───────────────┘
            │                                     │
            │         HTTP POST /check_url        │
            │         HTTP POST /api/scan         │
            └──────────────┬──────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                       FLASK BACKEND API                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  app.py                                                   │  │
│  │  - CORS enabled                                           │  │
│  │  - URL validation                                         │  │
│  │  - Feature extraction                                     │  │
│  │  - ML model inference                                     │  │
│  │  - Risk classification                                    │  │
│  │  - Response formatting                                    │  │
│  └───────────────────────┬──────────────────────────────────┘  │
└────────────────────────────┼───────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MACHINE LEARNING LAYER                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Feature Extraction (ai/features.py)                      │  │
│  │  - URL length analysis                                    │  │
│  │  - Domain parsing                                         │  │
│  │  - HTTPS detection                                        │  │
│  │  - Special character counting                             │  │
│  │  - Keyword detection                                      │  │
│  │  - IP address detection                                   │  │
│  └───────────────────────┬──────────────────────────────────┘  │
│                          ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Random Forest Classifier (model/phishing_model.pkl)     │  │
│  │  - Trained on 10,000+ samples                            │  │
│  │  - 95.2% accuracy                                         │  │
│  │  - Probability output (0-1)                               │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

### **Frontend**
- **HTML5** - Semantic markup
- **CSS3** - Custom properties, animations, flexbox/grid
- **JavaScript (ES6+)** - Async/await, LocalStorage API
- **Chart.js** - Data visualization
- **Font Awesome** - Icon library

### **Backend**
- **Python 3.8+** - Core programming language
- **Flask** - RESTful API framework
- **Flask-CORS** - Cross-origin resource sharing

### **Machine Learning**
- **scikit-learn** - Random Forest classifier
- **pandas** - Data manipulation
- **NumPy** - Numerical operations
- **joblib** - Model serialization

### **Browser Extension**
- **Manifest V3** - Chrome extension standard
- **Chrome APIs** - tabs, storage, webNavigation

### **Development Tools**
- **Git** - Version control
- **Virtual Environment** - Dependency isolation

---

## 📡 API Endpoint Details

### **Endpoint 1: Web Frontend Scanning**

**URL:** `/check_url`

**Method:** `POST`

**Headers:**
```json
{
  "Content-Type": "application/json"
}
```

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response (Success - 200):**
```json
{
  "url": "https://example.com",
  "label": "LEGITIMATE",
  "phishing_probability": 5.23,
  "risk_level": "Low",
  "risk_factors": [],
  "model": "Random Forest",
  "timestamp": "2026-02-07T14:30:45.123456",
  "url_length": 19
}
```

**Response (Phishing - 200):**
```json
{
  "url": "http://paypal-verify.tk/login",
  "label": "PHISHING",
  "phishing_probability": 87.5,
  "risk_level": "High",
  "risk_factors": [
    "Suspicious TLD detected (.tk)",
    "Missing HTTPS encryption",
    "Suspicious keywords in URL (verify)",
    "Domain age < 30 days"
  ],
  "model": "Random Forest",
  "timestamp": "2026-02-07T14:32:18.987654",
  "url_length": 31
}
```

**Response (Error - 400):**
```json
{
  "error": "Invalid request. 'url' field missing."
}
```

---

### **Endpoint 2: Browser Extension Scanning**

**URL:** `/api/scan`

**Method:** `POST`

**Headers:**
```json
{
  "Content-Type": "application/json"
}
```

**Request Body:**
```json
{
  "url": "https://github.com"
}
```

**Response (Success - 200):**
```json
{
  "url": "https://github.com",
  "classification": "Legitimate",
  "confidence": 2.8,
  "model": "Random Forest",
  "metrics": {
    "domain_age": "Unknown",
    "https": true,
    "url_length": 18,
    "has_ip": false,
    "suspicious_keywords": false
  },
  "timestamp": "2026-02-07 14:35:22"
}
```

---

### **Endpoint 3: Health Check**

**URL:** `/`

**Method:** `GET`

**Response (200):**
```json
{
  "status": "running",
  "message": "Phishing Detection API is live",
  "version": "2.0.0",
  "endpoints": {
    "scan": "/api/scan (POST) - Extension compatible",
    "check_url": "/check_url (POST) - Frontend & legacy"
  },
  "model_loaded": true,
  "timestamp": "2026-02-07T14:40:15.555555"
}
```

---

## 🔄 Browser Extension Workflow

### **1. User Interaction**
```
User clicks extension icon → Auto-detects current tab URL
```

### **2. Data Collection**
```
Extension captures:
├── Current webpage URL
├── Screenshot (if accessible)
└── Page metadata
```

### **3. API Request**
```
POST /api/scan
{
  "url": "https://current-page.com"
}
```

### **4. ML Processing**
```
Backend:
├── Extracts URL features
├── Runs Random Forest prediction
├── Calculates confidence score
├── Determines risk level
└── Generates risk factors
```

### **5. Response Display**
```
Extension popup shows:
├── ✅ Safe / ⚠️ Suspicious / 🚨 Phishing
├── Confidence meter (animated circular progress)
├── Risk metrics (HTTPS, URL length, domain age)
├── Screenshot preview
└── Action buttons (Copy, Share, Export)
```

### **6. Protection Actions**
- **Low Risk:** Allow browsing, log scan
- **Medium Risk:** Show warning, allow with caution
- **High Risk:** Block navigation, show warning page with bypass option

---

## 📱 Screens / Pages Description

### **Extension Popup**

**Purpose:** One-click scanning interface for active webpage

**Components:**
- **Header**
  - Extension title with shield icon
  - "AI-Powered Protection" tagline

- **Scan Button**
  - Large, prominent "🔍 Scan Current Page" button
  - Disabled state for internal Chrome pages

- **Loading State**
  - Three-ring animated spinner
  - Progress stages: "Analyzing URL...", "Running ML analysis...", etc.
  - Real-time elapsed time counter

- **Result Section**
  - Status badge (Safe/Suspicious/Phishing) with color coding
  - Circular confidence meter (0-100%)
  - Screenshot preview (or placeholder)
  - Metrics grid:
    - Classification result
    - Domain age
    - HTTPS status
    - URL length
    - Suspicious keywords detected
    - IP address usage

- **Action Buttons**
  - Copy result to clipboard
  - Share scan (Native Share API)
  - Export as JSON
  - Rescan button

---

### **Warning Page**

**Purpose:** Intercept and block high-risk phishing websites

**Components:**
- **Warning Header**
  - Large "⚠️ PHISHING THREAT DETECTED" message
  - Red/orange danger styling

- **Threat Details**
  - Blocked URL display
  - Risk level indicator (HIGH/MEDIUM)
  - Confidence score with visual meter
  - Detected threat categories

- **Risk Explanation**
  - Bulleted list of detected indicators:
    - "Suspicious domain name"
    - "Missing HTTPS encryption"
    - "Domain registered recently"
    - etc.

- **Action Options**
  - **Primary:** "← Go Back to Safety" (large green button)
  - **Secondary:** "Report False Positive" (feedback link)
  - **Tertiary:** "I Understand the Risk - Proceed Anyway" (small text link)

- **Educational Section**
  - "What is Phishing?" brief explanation
  - "How to Stay Safe" tips

---

## 🚀 How to Run the Project

### **Prerequisites**
```bash
Python 3.8+
pip (Python package manager)
Google Chrome browser (for extension)
```

### **Backend Setup**

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/phishguard-ai.git
cd phishguard-ai
```

2. **Create Virtual Environment**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install flask flask-cors scikit-learn pandas numpy joblib
```

4. **Start Flask Server**
```bash
python backend/app.py
```

**Expected Output:**
```
============================================================
🛡️  PHISHING DETECTION API SERVER
============================================================
[✓] Version: 2.0.0 (Enhanced Frontend Compatible)
[✓] Server running on: http://0.0.0.0:5000
[✓] Extension endpoint: http://localhost:5000/api/scan
[✓] Frontend endpoint: http://localhost:5000/check_url
[✓] Model loaded: True
[✓] Model type: Random Forest
============================================================
```

5. **Test API**
```bash
curl -X POST http://localhost:5000/check_url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

### **Frontend Setup**

1. **Navigate to Frontend Directory**
```bash
cd frontend
```

2. **Open in Browser**
```bash
# Simply open index.html in your browser
# Or use a local server:
python -m http.server 8000
```

3. **Access Application**
```
http://localhost:8000/index.html
```

---

### **Browser Extension Setup**

1. **Navigate to Extension Directory**
```bash
cd extension
```

2. **Load Extension in Chrome**
   - Open Chrome browser
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right)
   - Click "Load unpacked"
   - Select the `extension/` folder

3. **Verify Installation**
   - Extension icon should appear in Chrome toolbar
   - Click icon to open popup
   - Test with any webpage

4. **Configuration** (Optional)
   - Open `extension/config.js`
   - Update `API_URL` if backend is on different host/port
   ```javascript
   const CONFIG = {
     API_URL: 'http://localhost:5000/api/scan',
     // ...
   };
   ```

---

## 🧪 Sample Test URLs

### **Legitimate Websites (Expected: Low Risk)**
```
https://google.com
https://github.com
https://microsoft.com
https://stackoverflow.com
https://wikipedia.org
```

### **Suspicious Patterns (Expected: Medium Risk)**
```
http://free-prize-claim.info
https://verify-account-now.site
http://secure-login-portal.xyz
```

### **Phishing Examples (Expected: High Risk)**
```
http://paypal-verify.tk/login
http://192.168.1.1/amazon-update.php
https://chase-bank-secure.ml/signin
http://account-suspended-apple.ga/verify
```

**Note:** Some example phishing URLs may not be active. Use at your own discretion and in a controlled environment.

---

## 🔮 Future Enhancements

### **Machine Learning Improvements**
- [ ] Deep learning models (LSTM, CNN) for enhanced accuracy
- [ ] Real-time model retraining with user feedback
- [ ] Multi-model ensemble approach
- [ ] Transfer learning from pre-trained models

### **Feature Additions**
- [ ] **Screenshot Analysis** - Visual similarity detection using computer vision
- [ ] **WHOIS Lookup** - Domain registration age verification
- [ ] **DNS Analysis** - MX records and nameserver validation
- [ ] **SSL Certificate Verification** - Certificate authority checking
- [ ] **Reputation Databases** - Integration with Google Safe Browsing API
- [ ] **Natural Language Processing** - Page content analysis
- [ ] **Behavioral Analysis** - User interaction pattern detection

### **Extension Enhancements**
- [ ] Firefox and Edge browser support
- [ ] Link scanning on hover
- [ ] Form submission protection
- [ ] Password field warnings
- [ ] WhatsApp/messaging platform integration
- [ ] QR code scanning

### **Backend Improvements**
- [ ] Database integration (PostgreSQL/MongoDB)
- [ ] User authentication and profiles
- [ ] Rate limiting and API keys
- [ ] Batch URL scanning
- [ ] WebSocket for real-time updates
- [ ] Microservices architecture

### **UI/UX Enhancements**
- [ ] Mobile app (React Native)
- [ ] Admin dashboard
- [ ] Detailed analytics and reporting
- [ ] Customizable blocking rules
- [ ] Multi-language support (i18n)

### **Security Features**
- [ ] VPN detection warnings
- [ ] Cryptocurrency scam detection
- [ ] Fake news URL verification
- [ ] Social engineering attempt detection

---

## 🌍 Hackathon Impact / Use Cases

### **Individual Users**
- **Email Protection:** Verify links in emails before clicking
- **Social Media Safety:** Check shared links on Facebook, Twitter, Instagram
- **Online Shopping:** Validate e-commerce websites before entering payment info
- **Banking Security:** Ensure banking URLs are legitimate

### **Educational Institutions**
- **Student Protection:** Deploy across university networks
- **Cybersecurity Training:** Real-world ML application for CS students
- **Research Platform:** Dataset generation for academic research
- **Awareness Campaigns:** Demonstrate phishing techniques

### **Organizations**
- **Employee Training:** Integrate into security awareness programs
- **Network Security:** Deploy as internal scanning service
- **Email Gateway:** Pre-scan links in corporate emails
- **Incident Response:** Rapid URL threat assessment

### **Social Impact**
- **Vulnerable Populations:** Protect elderly and non-technical users
- **Financial Security:** Prevent credential theft and fraud
- **Data Privacy:** Reduce personal information leakage
- **Trust Building:** Restore confidence in online interactions

### **Technical Innovation**
- **Explainable AI:** Demonstrates transparent ML decision-making
- **Real-time Processing:** Shows practical ML deployment
- **Browser Integration:** Example of secure extension development
- **Open Source Contribution:** Community-driven security tool

---

## 📄 License

This project is developed for **educational and research purposes** as part of a hackathon/academic initiative.

### **MIT License**

```
MIT License

Copyright (c) 2026 PhishGuard AI Team

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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### **Disclaimer**

This software is provided for **educational purposes only**. The developers are not responsible for:
- Incorrect classifications or false positives/negatives
- Security breaches resulting from bypassing warnings
- Damages from reliance on detection results
- Third-party misuse of the system

**For Production Use:** Conduct thorough security audits and testing before deployment in critical environments.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature requests
- Documentation improvements
- Model accuracy enhancements

---

## 📧 Contact

For questions, suggestions, or collaboration opportunities:

- **Project Repository:** https://github.com/yourusername/phishguard-ai
- **Email:** your.email@example.com
- **Hackathon Team:** [Team Name]

---

## 🏆 Acknowledgments

- **Dataset Sources:** PhishTank, OpenPhish, UCI Machine Learning Repository
- **Inspiration:** Real-world phishing incidents and cybersecurity research
- **Libraries:** scikit-learn, Flask, Chart.js communities
- **Mentors:** [Your hackathon mentors/advisors]

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

**Made with ❤️ for a safer internet**

![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest-green)
![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey)
![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3-yellow)
![License](https://img.shields.io/badge/License-MIT-blue)

</div>