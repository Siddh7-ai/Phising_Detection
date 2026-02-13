# 🛡️ PhishGuard AI – Intelligent Phishing Detection System

**PhishGuard AI** is a real-time, machine learning–powered phishing detection system designed to protect users from malicious websites before sensitive information is exposed. It combines a **Random Forest ML model**, a **Flask REST API**, a **web dashboard**, and a **browser extension** to deliver fast, explainable, and user-friendly phishing detection.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Solution](#-our-solution)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [API Documentation](#-api-documentation)
- [Machine Learning Model](#-machine-learning-model)
- [Browser Extension](#-browser-extension)
- [Hackathon Highlights](#-hackathon-highlights)
- [Roadmap](#-roadmap)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)
- [Team](#-teams)

---

## 🌟 Overview

PhishGuard AI analyzes URLs using advanced feature engineering and machine learning to determine whether a website is **Legitimate**, **Suspicious**, or **Phishing**. It is built for:

- Individual users
- Educational institutions
- Hackathons & research
- Future enterprise deployment

---

## 🎯 Problem Statement

- Billions of phishing attacks occur every year
- Users cannot easily distinguish fake websites
- Traditional blacklists fail against newly generated phishing URLs
- Phishing leads to credential theft, financial fraud, and identity loss

---

## 💡 Our Solution

PhishGuard AI provides:

- Real-time phishing detection
- High-accuracy ML-based classification
- Explainable AI risk indicators
- Browser-level protection
- Web-based scanning dashboard

---

## ✨ Key Features

### 🛡️ Core Features

| Feature | Description |
|---------|-------------|
| Real-Time URL Scanning | ML-based detection within seconds |
| Browser Extension | One-click scan of current webpage |
| Web Dashboard | Interactive UI for scanning URLs |
| Confidence Scoring | Probability-based threat score |
| Risk Classification | Legitimate / Suspicious / Phishing |
| Explainable AI | Detailed feature-based explanations |
| Screenshot Capture | Visual verification of scanned page |
| Scan History | Stored locally for review |
| WhatsApp Web Protection | Scans shared links |

---

## 🏗️ System Architecture

```
User Interface (Web + Extension)
            |
            v
REST API (Flask Backend)
            |
            v
Feature Engineering Layer
            |
            v
Random Forest ML Model
```

---

## 🛠️ Tech Stack

### Backend & Machine Learning

- Python 3.8+
- Flask
- Flask-CORS
- scikit-learn
- pandas
- NumPy
- joblib

### Frontend

- HTML5
- CSS3 (CSS Variables)
- JavaScript (ES6+)
- Chart.js

### Browser Extension

- Chrome Extension (Manifest V3)
- Chrome APIs
- Service Worker

---

## 💻 Installation & Setup

### Prerequisites

- Python 3.8+
- pip
- Google Chrome
- Git

---

### Backend Setup

```bash
git clone https://github.com/yourusername/phishguard-ai.git
cd phishguard-ai

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/macOS

pip install flask flask-cors scikit-learn pandas numpy joblib

cd backend
python app.py
```

### Frontend Setup

```bash
cd frontend
python -m http.server 8000
```

Open: `http://localhost:8000/index.html`

### Browser Extension Setup

1. Open Chrome
2. Go to `chrome://extensions/`
3. Enable **Developer Mode**
4. Click **Load unpacked**
5. Select the `extension/` folder

---

## 📖 Usage Guide

### Web Dashboard

1. Enter URL
2. Click **Scan**
3. View classification, confidence, and risk factors

### Browser Extension

1. Click extension icon
2. Scan current webpage
3. View result with confidence and screenshot

---

## 📡 API Documentation

### POST /api/scan

**Request**

```json
{
  "url": "https://example.com"
}
```

**Response**

```json
{
  "url": "https://example.com",
  "classification": "Legitimate",
  "confidence": 2.8,
  "model": "Random Forest",
  "metrics": {
    "https": true,
    "url_length": 19,
    "has_ip": false,
    "suspicious_keywords": false
  }
}
```

---

## 🤖 Machine Learning Model

- **Algorithm:** Random Forest Classifier
- **Training Samples:** 10,000+ URLs
- **Accuracy:** 95.2%
- **Precision:** 94.8%
- **Recall:** 96.1%
- **F1-Score:** 95.4%

### Features Used

- URL length
- Special characters
- HTTPS detection
- IP address usage
- Domain structure
- Suspicious keywords
- TLD analysis

---

## 🔌 Browser Extension

```
extension/
├── manifest.json
├── popup.html
├── popup.js
├── background.js
├── content.js
├── whatsapp.js
├── warning.html
├── warning.js
├── config.js
└── icons/
```

### Extension Capabilities

- One-click scanning
- Dynamic color themes
- Screenshot preview
- Risk-based warnings
- Confidence visualization

---

## 🏆 Hackathon Highlights

- Solves real-world cybersecurity problem
- High ML accuracy with explainability
- Clean UI/UX with cyber-green theme
- Production-ready architecture
- Scalable API-based design

---

## 🗺️ Roadmap

### Phase 1 (Completed)

- ✅ ML Model
- ✅ REST API
- ✅ Web UI
- ✅ Chrome Extension

### Phase 2

- Deep learning models
- Domain age verification
- SSL certificate checks

### Phase 3

- Firefox & Edge extensions
- Mobile app
- Email phishing detection

### Phase 4

- Enterprise dashboard
- Authentication
- Analytics & reports

---

## 🧪 Testing

### Safe URLs

```
https://google.com
https://github.com
```

### Phishing URLs (Testing Only)

```
http://paypal-verify.tk/login
http://192.168.1.1/amazon-update.php
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push and open a pull request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👥 Team

- **ML Engineer & Backend Developer** – [Japesh Patel]
- **Frontend Developer & UI/UX Designer** – [Siddharthsinh Raulji]
- **Extension Developer & Security Analyst** – [Dharmit Monani]

---

⭐ **Support**

If you find this project useful, consider starring the repository.

*Protecting the digital world, one URL at a time.*