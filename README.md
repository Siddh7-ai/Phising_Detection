=== README.md ===
# 🛡️ PhishGuard AI — Phishing Website Detection System

A **complete, end-to-end phishing website detection system** built for a **national-level hackathon**.  
PhishGuard AI combines **Machine Learning**, **Explainable AI**, and a **modern cybersecurity UI** to help users instantly identify malicious websites with confidence and clarity.

---

## 🚨 Problem Overview

Phishing websites impersonate trusted brands to steal:
- Login credentials
- Banking information
- Personal data

Most users cannot reliably distinguish a phishing URL from a legitimate one.  
A **single false negative** (missing a phishing site) can cause serious harm.

---

## ✅ Solution Summary

**PhishGuard AI** provides:

- Real-time phishing detection using Machine Learning  
- **Security-first design** (high recall, fewer missed attacks)  
- Clear, human-readable explanations (Explainable AI)  
- A dark, neon, hacker-style dashboard that judges immediately trust  

---

## 🧠 System Architecture



User (Browser)
↓
Frontend (HTML / CSS / JavaScript)
↓ REST API
Backend (Flask)
↓
AI Layer (Random Forest - Scikit-learn)


### End-to-End Flow
1. User enters a website URL  
2. Frontend sends the URL to Flask API  
3. Backend extracts URL features  
4. ML model predicts phishing probability  
5. Explainable risk factors are generated  
6. Result is displayed with confidence and risk level  

---

## ✨ Core Features

### 🎨 Frontend (Cybersecurity UI)
- Dark mode with neon green / red accents  
- Hacker-style professional dashboard  
- Large centered URL input  
- Loading scan animation  
- Result card with:
  - SAFE (green)
  - SUSPICIOUS (yellow)
  - PHISHING (red)
- Confidence score (%)  
- Clear list of detected phishing indicators  
- Fully responsive (mobile + desktop)  

### ⚙️ Backend (Flask API)
- REST endpoint: `POST /check_url`  
- Loads ML model once at startup  
- Input validation & error handling  
- Fast inference  
- CORS enabled for frontend integration  

### 🤖 AI / Machine Learning
- Algorithm: **Random Forest Classifier**
- Built using **Scikit-learn**
- Focus on **high recall** (security-first)
- Simple, interpretable features

---

## 🧪 Why Random Forest?

Random Forest was chosen because it:
- Handles non-linear URL patterns well  
- Is robust to noisy data  
- Provides feature importance (explainable)  
- Performs well with small-to-medium datasets  
- Allows recall to be prioritized over accuracy  

> In cybersecurity, **missing an attack is worse than raising a warning**.

---

## 🔍 Features Used for Detection

The model analyzes each URL using:

- URL length  
- Number of dots (subdomains)  
- Presence of `@` symbol  
- Presence of hyphens (`-`)  
- IP address instead of domain  
- HTTPS usage  
- Phishing-related keywords:
  - `login`
  - `verify`
  - `secure`
  - `account`
  - `update`
  - `bank`

---

## 🧠 Explainable AI (XAI)

For every prediction, PhishGuard AI explains **WHY**:

Examples:
- “URL contains many subdomains, a known phishing tactic”
- “Phishing-related keyword detected: ‘login’”
- “Website does not use HTTPS”
- “URL uses an IP address instead of a domain name”

This makes the system:
- Judge-friendly  
- User-trustworthy  
- Easy to defend during evaluation  

---

## 📊 Model Training & Evaluation

During training (`ai/train_model.py`):

- Dataset is split: **80% train / 20% test**
- Metrics printed:
  - Accuracy
  - Precision
  - **Recall**
  - Confusion Matrix

Recall is intentionally emphasized to reduce false negatives.

---

## 📁 Strict Project Structure



phishing_detection_system/
├── frontend/
│ ├── index.html
│ ├── style.css
│ └── script.js
├── backend/
│ ├── app.py
│ └── model.pkl
├── ai/
│ ├── train_model.py
│ └── features.py
├── data/
│ └── sample_urls.csv
├── requirements.txt
└── README.md


⚠️ Structure is mandatory and hackathon-safe.

---

## ⚙️ Setup & Execution Guide

### 1️⃣ Clone Repository
```bash
git clone <repository-url>
cd phishing_detection_system

2️⃣ Create Virtual Environment (Recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Train the Machine Learning Model
cd ai
python train_model.py


➡️ This generates:

backend/model.pkl

5️⃣ Run the Backend Server
cd backend
python app.py


Backend runs at:

http://127.0.0.1:5000

6️⃣ Launch Frontend

Open frontend/index.html in your browser.

🔌 Sample API Usage
Request

POST /check_url

{
  "url": "https://secure-login-google.com/login"
}

Response
{
  "label": "PHISHING",
  "confidence": 0.92,
  "risk_level": "High",
  "risk_factors": [
    "URL is unusually long, which is common in phishing attacks",
    "Phishing-related keyword detected: 'login'",
    "Domain contains hyphens, frequently seen in fake websites"
  ]
}