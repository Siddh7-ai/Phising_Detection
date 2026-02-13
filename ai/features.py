# === ai/features.py ===
"""
features.py (COMPREHENSIVE VERSION - v2.1 PATCH)
-----------------------------------------
URL feature extraction logic for Phishing Website Detection System.

PATCH v2.1 CHANGES:
- Added claude.ai, anthropic.com, openai.com to TRUSTED_DOMAINS
- This fixes false positive for Claude AI chat URLs with UUIDs

IMPORTANT: After updating this file, you MUST retrain the model:
    python ai/train_model.py

The old model was trained without these domains in the trusted list,
so Feature #14 will now return 1 instead of 0 for these domains.
"""

import re
from urllib.parse import urlparse


# ============================================================================
# TRUSTED PATTERNS
# ============================================================================

# Educational TLDs (universities, colleges, schools)
EDUCATIONAL_TLDS = [
    '.edu', '.edu.in', '.edu.au', '.edu.cn', '.edu.sg', '.edu.my',
    '.ac.in', '.ac.uk', '.ac.jp', '.ac.kr', '.ac.nz', '.ac.za',
    '.edu.br', '.edu.ar', '.edu.mx', '.edu.pk', '.edu.bd',
    '.ernet.in',  # Indian education/research network
]

# Government TLDs
GOVERNMENT_TLDS = [
    '.gov', '.gov.in', '.gov.uk', '.gov.au', '.gov.sg', '.gov.cn',
    '.mil', '.mil.in',
    '.nic.in',  # National Informatics Centre (India)
]

# Non-profit/Organization TLDs
NONPROFIT_TLDS = [
    '.org', '.ngo', '.ong',
]

# Country code TLDs (generally legitimate)
COUNTRY_TLDS = [
    '.in', '.uk', '.us', '.ca', '.au', '.de', '.fr', '.jp', '.cn',
    '.br', '.ru', '.it', '.es', '.nl', '.se', '.ch', '.no', '.dk',
]

# Major trusted domains and companies
TRUSTED_DOMAINS = [
    # Tech Giants
    'google', 'microsoft', 'apple', 'amazon', 'meta', 'facebook',
    'twitter', 'x.com', 'linkedin', 'netflix', 'adobe', 'oracle',
    'ibm', 'cisco', 'intel', 'nvidia', 'amd', 'dell', 'hp',
    # Developer / Tech Services
    'github', 'gitlab', 'bitbucket', 'stackoverflow', 'stackexchange',
    'npmjs', 'pypi', 'docker', 'kubernetes', 'cloudflare', 'aws.amazon',
    # Cloud Providers
    'azure', 'googleapis', 'cloudfront', 'digitalocean', 'heroku',
    'vercel', 'netlify', 'firebase',
    # CDNs & Infrastructure
    'akamai', 'fastly', 'jsdelivr', 'unpkg', 'cdnjs',
    # Email / Communication
    'gmail', 'outlook', 'yahoo', 'protonmail', 'zoom', 'slack',
    'teams', 'whatsapp', 'telegram',
    # Media & Content
    'youtube', 'vimeo', 'spotify', 'twitch', 'reddit', 'medium',
    'wordpress', 'blogger', 'tumblr',
    # Education / Research
    'wikipedia', 'wikimedia', 'coursera', 'udemy', 'edx', 'khan',
    # PATCH v2.1: AI Companies (NEW)
    'claude.ai', 'anthropic.com', 'openai.com', 'chatgpt.com',
    'perplexity.ai', 'poe.com',
    # Indian Companies / Services
    'flipkart', 'paytm', 'phonepe', 'gpay', 'bhim', 'upi',
    'irctc', 'uidai', 'epfindia', 'incometax',
    # Major Indian Banks
    'sbi.co.in', 'hdfcbank', 'icicibank', 'axisbank', 'pnb',
    'kotakbank', 'yesbank', 'indusind',
    # Other Trusted
    'mozilla', 'w3.org', 'ietf.org', 'iso.org',
]

# Subdomain prefixes that are legitimate by themselves
LEGITIMATE_SUBDOMAINS = [
    'mail', 'webmail', 'email', 'smtp', 'imap', 'pop',
    'www', 'blog', 'news', 'shop', 'store', 'cart',
    'cdn', 'static', 'assets', 'media', 'img', 'images',
    'api', 'dev', 'staging', 'test', 'demo',
    'docs', 'wiki', 'help', 'support', 'kb',
    'login', 'auth', 'oauth', 'sso', 'accounts',
    'secure', 'ssl',
    'portal', 'dashboard', 'admin',
    'cloud', 'drive', 'files',
    'meet', 'video', 'conference',
    'chat',  # PATCH v2.1: Added 'chat' for Claude AI (NEW)
]

# ============================================================================
# ORIGINAL KEYWORDS (unchanged from v1 for backward compatibility)
# ============================================================================

PHISHING_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
]

# Additional phishing keywords used only in new features (12–18)
EXTENDED_PHISHING_KEYWORDS = [
    "verify", "suspended", "locked", "unusual", "confirm",
    "update", "billing", "payment", "expire", "limited",
    "alert", "urgent", "action", "required", "security",
    "validation", "authenticate",
]

# Banking keywords — high risk if NOT from a known bank domain
BANKING_KEYWORDS = [
    "bank", "account", "netbanking", "wallet", "card",
    "credit", "debit", "transaction", "transfer",
]

SPECIAL_CHARS_PATTERN = re.compile(r"[^a-zA-Z0-9]")


# ============================================================================
# ORIGINAL HELPER FUNCTIONS (v1 — unchanged)
# ============================================================================

def has_ip_address(url: str) -> int:
    """Check if URL uses IP address instead of domain name."""
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0


def count_phishing_keywords(url: str) -> int:
    """Count original phishing keywords (v1 behaviour, used for feature 7)."""
    url_lower = url.lower()
    return sum(1 for keyword in PHISHING_KEYWORDS if keyword in url_lower)


def has_suspicious_keyword(url: str) -> int:
    """Binary indicator — original v1 keyword list (used for feature 11)."""
    url_lower = url.lower()
    return 1 if any(keyword in url_lower for keyword in PHISHING_KEYWORDS) else 0


# ============================================================================
# NEW HELPER FUNCTIONS (v2 — used only for features 12–18)
# ============================================================================

def is_educational_domain(url: str) -> int:
    """Check if URL is from an educational institution."""
    url_lower = url.lower()
    return 1 if any(tld in url_lower for tld in EDUCATIONAL_TLDS) else 0


def is_government_domain(url: str) -> int:
    """Check if URL is from a government website."""
    url_lower = url.lower()
    return 1 if any(tld in url_lower for tld in GOVERNMENT_TLDS) else 0


def is_nonprofit_domain(url: str) -> int:
    """Check if URL is from a non-profit organisation."""
    url_lower = url.lower()
    return 1 if any(tld in url_lower for tld in NONPROFIT_TLDS) else 0


def is_country_tld(url: str) -> int:
    """Check if URL uses a country-code TLD."""
    url_lower = url.lower()
    for tld in COUNTRY_TLDS:
        if (url_lower.endswith(tld)
                or tld + '/' in url_lower
                or tld + '?' in url_lower):
            return 1
    return 0


def is_trusted_domain(url: str) -> int:
    """
    Check if URL belongs to a known trusted organisation.
    
    PATCH v2.1: Now includes claude.ai, anthropic.com, openai.com
    """
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    domain = parsed.netloc
    return 1 if any(trusted in domain for trusted in TRUSTED_DOMAINS) else 0


def count_banking_keywords_safe(url: str) -> int:
    """
    Count banking keywords — returns 0 if domain is already trusted,
    so known banks don't get penalised.
    """
    if is_trusted_domain(url):
        return 0
    url_lower = url.lower()
    return sum(1 for kw in BANKING_KEYWORDS if kw in url_lower)


def has_legitimate_subdomain(url: str) -> int:
    """
    Check whether the subdomain prefix is a known-legitimate pattern.
    
    PATCH v2.1: Now includes 'chat' subdomain
    """
    parsed = urlparse(url.lower())
    netloc = parsed.netloc
    parts = netloc.split('.')
    if len(parts) > 2:
        subdomain = parts[0]
        return 1 if subdomain in LEGITIMATE_SUBDOMAINS else 0
    return 0


# ============================================================================
# MAIN FEATURE EXTRACTION
# ============================================================================

def extract_features(url: str) -> list:
    """
    Extract numerical features from a URL.

    Feature order is FIXED and must match training & inference.

    Features (18 total):
    ── ORIGINAL (1–11, identical to v1) ──────────────────────────
    1.  URL length (raw character count)
    2.  Number of dots
    3.  Presence of '@'
    4.  Presence of '-'
    5.  Presence of IP address
    6.  HTTPS usage
    7.  Count of phishing keywords (original 6-word list)
    8.  Count of digits in URL
    9.  Count of special characters
    10. Number of subdomains
    11. Presence of suspicious keyword — binary (original list)
    ── NEW (12–18) ─────────────────────────────────────────────────
    12. Is educational domain (.edu, .ac.in, etc.)
    13. Is government domain (.gov, .gov.in, etc.)
    14. Is trusted domain (major companies / Indian banks / AI companies)
    15. Is non-profit domain (.org, .ngo)
    16. Has country-code TLD (.in, .uk, .au, etc.)
    17. Count of banking keywords (0 if domain already trusted)
    18. Has legitimate subdomain prefix (mail, portal, api, chat, etc.)
    """

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()

    features = []

    # ── ORIGINAL FEATURES (1–11) — DO NOT REORDER ──────────────────

    # 1. URL length
    features.append(len(url))

    # 2. Number of dots
    features.append(url.count("."))

    # 3. Presence of '@'
    features.append(1 if "@" in url else 0)

    # 4. Presence of '-' (ONLY in domain)
    features.append(1 if "-" in netloc else 0)

    # 5. IP address usage
    features.append(has_ip_address(url))

    # 6. HTTPS usage
    features.append(1 if parsed.scheme == "https" else 0)

    # 7. Phishing keyword count (original 6-word list)
    features.append(count_phishing_keywords(url))

    # 8. Count of digits (ONLY in domain)
    features.append(sum(char.isdigit() for char in netloc))
    
    # 9. Count of special characters (ONLY in domain)
    features.append(len(SPECIAL_CHARS_PATTERN.findall(netloc)))


    # 10. Number of subdomains
    if netloc:
        parts = netloc.split(".")
        features.append(max(len(parts) - 2, 0))
    else:
        features.append(0)

    # 11. Suspicious keyword presence (binary, original list)
    features.append(has_suspicious_keyword(url))

    # ── NEW FEATURES (12–18) ────────────────────────────────────────

    # 12. Educational domain
    features.append(is_educational_domain(url))

    # 13. Government domain
    features.append(is_government_domain(url))

    # 14. Trusted domain (PATCH v2.1: now includes AI companies)
    features.append(is_trusted_domain(url))

    # 15. Non-profit domain
    features.append(is_nonprofit_domain(url))

    # 16. Country-code TLD
    features.append(is_country_tld(url))

    # 17. Banking keywords (context-aware, 0 if trusted)
    features.append(count_banking_keywords_safe(url))

    # 18. Legitimate subdomain prefix (PATCH v2.1: now includes 'chat')
    features.append(has_legitimate_subdomain(url))

    return features


# ============================================================================
# EXPLAIN / DEBUG
# ============================================================================

def explain_features(url: str) -> list:
    """Generate human-readable explanations for URL risk signals."""
    explanations = []
    parsed = urlparse(url)
    url_lower = url.lower()

    # Trust indicators first
    trust_score = 0

    if is_educational_domain(url):
        explanations.append("✓ Educational institution domain (.edu / .ac)")
        trust_score += 3

    if is_government_domain(url):
        explanations.append("✓ Government website (.gov / .mil)")
        trust_score += 3

    if is_trusted_domain(url):
        explanations.append("✓ Known trusted organisation")
        trust_score += 2

    if is_nonprofit_domain(url):
        explanations.append("✓ Non-profit organisation (.org)")
        trust_score += 1

    if is_country_tld(url):
        explanations.append("✓ Uses country-code domain")
        trust_score += 1

    # If highly trusted, skip risk checks
    if trust_score >= 3:
        return explanations

    # Risk signals
    if len(url) > 75:
        explanations.append("⚠ URL is unusually long")

    if url.count(".") > 3:
        explanations.append("⚠ Multiple subdomains detected")

    if "@" in url:
        explanations.append("⚠ URL contains '@' symbol")

    if "-" in parsed.netloc and not is_trusted_domain(url):
        explanations.append("⚠ Hyphenated domain name")

    if has_ip_address(url):
        explanations.append("⚠ IP address used instead of domain name")

    if parsed.scheme != "https":
        explanations.append("⚠ Website does not use HTTPS")

    for keyword in PHISHING_KEYWORDS:
        if keyword in url_lower:
            explanations.append(f"⚠ Suspicious keyword detected: '{keyword}'")

    banking_count = count_banking_keywords_safe(url)
    if banking_count > 0:
        explanations.append(f"⚠ Contains {banking_count} banking-related keyword(s) on unknown domain")

    if not explanations:
        explanations.append("✓ No obvious threats detected")

    return explanations


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def get_feature_count() -> int:
    """Return the expected number of features."""
    return 18


def validate_features(features: list) -> bool:
    """Validate that a feature vector has the correct length."""
    return len(features) == get_feature_count()