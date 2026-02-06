# === ai/features.py ===
"""
features.py
------------
URL feature extraction logic for Phishing Website Detection System.

This module converts a raw URL into a numerical feature vector
used by the Machine Learning model.

Focus:
- Simple, explainable features
- Security-first (bias towards detecting phishing)
- Compatible with scikit-learn
"""

import re
from urllib.parse import urlparse


# Common phishing-related keywords (can be expanded later)
PHISHING_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank"
]


def has_ip_address(url: str) -> int:
    """
    Check if the URL contains an IP address instead of a domain name.
    Example: http://192.168.0.1/login
    """
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0


def count_phishing_keywords(url: str) -> int:
    """
    Count how many known phishing keywords appear in the URL.
    """
    url_lower = url.lower()
    return sum(1 for keyword in PHISHING_KEYWORDS if keyword in url_lower)


def extract_features(url: str) -> list:
    """
    Extract numerical features from a URL.

    Returns a list of features in a FIXED ORDER.
    This order MUST match training and inference.

    Feature list:
    1. URL length
    2. Number of dots
    3. Presence of '@' symbol
    4. Presence of '-' (hyphen)
    5. Presence of IP address
    6. HTTPS usage (1 if https, else 0)
    7. Number of phishing keywords
    """

    parsed = urlparse(url)

    features = []

    # 1. URL length
    features.append(len(url))

    # 2. Number of dots
    features.append(url.count("."))

    # 3. Presence of '@'
    features.append(1 if "@" in url else 0)

    # 4. Presence of '-'
    features.append(1 if "-" in url else 0)

    # 5. IP address usage
    features.append(has_ip_address(url))

    # 6. HTTPS usage
    features.append(1 if parsed.scheme == "https" else 0)

    # 7. Phishing keyword count
    features.append(count_phishing_keywords(url))

    return features


def explain_features(url: str) -> list:
    """
    Generate human-readable explanations for triggered phishing indicators.
    Used for Explainable AI (XAI).

    Returns a list of explanation strings.
    """
    explanations = []
    parsed = urlparse(url)
    url_lower = url.lower()

    if len(url) > 75:
        explanations.append("URL is unusually long, which is common in phishing attacks")

    if url.count(".") > 3:
        explanations.append("URL contains many subdomains, a known phishing tactic")

    if "@" in url:
        explanations.append("URL contains '@' symbol, often used to mislead users")

    if "-" in parsed.netloc:
        explanations.append("Domain contains hyphens, frequently seen in fake websites")

    if has_ip_address(url):
        explanations.append("URL uses an IP address instead of a domain name")

    if parsed.scheme != "https":
        explanations.append("Website does not use HTTPS (no secure connection)")

    for keyword in PHISHING_KEYWORDS:
        if keyword in url_lower:
            explanations.append(f"Phishing-related keyword detected: '{keyword}'")

    return explanations
