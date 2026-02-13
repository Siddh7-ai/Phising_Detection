"""
add_comprehensive_urls.py
--------------------------
Comprehensive URL dataset builder for phishing detection model training.

This addresses ALL potential false positive scenarios:
1.  Educational institutions (.edu, .ac.in, .edu.in, etc.)
2.  Government websites (.gov, .gov.in, .nic.in, etc.)
3.  E-commerce platforms (Amazon, Flipkart, eBay, etc.)
4.  Banking & financial services (SBI, HDFC, ICICI, Paytm, etc.)
5.  Cloud services & CDNs (Google Drive, Azure, Cloudflare, etc.)
6.  Developer tools & platforms (GitHub, PyPI, Docker, etc.)
7.  Corporate login pages (accounts.google.com, login.microsoft.com)
8.  Non-profit organisations (Wikipedia, Mozilla, W3C, etc.)
9.  International domains (.uk, .au, .sg, etc.)
10. Long URLs from legitimate sources (Google Docs, Amazon tracking, etc.)
11. Legitimate subdomains (mail., portal., api., etc.)
12. Social media & communication (LinkedIn, Zoom, Slack, etc.)
13. News & media outlets (BBC, Reuters, etc.)
14. Streaming & entertainment (Netflix, Spotify, YouTube, etc.)
15. Healthcare & insurance portals

Run this BEFORE training to dramatically reduce false positives!

Usage:
    python ai/add_comprehensive_urls.py
"""

import os
import pandas as pd


# ============================================================================
# LEGITIMATE URLS — Comprehensive Coverage (180+ URLs)
# ============================================================================

LEGITIMATE_URLS = [

    # ── INDIAN UNIVERSITIES & COLLEGES ──────────────────────────────
    "https://charusat.edu.in",
    "https://charusat.ac.in",
    "https://iitb.ac.in",
    "https://iitd.ac.in",
    "https://iitm.ac.in",
    "https://iitk.ac.in",
    "https://iith.ac.in",
    "https://iitkgp.ac.in",
    "https://iisc.ac.in",
    "https://bits-pilani.ac.in",
    "https://nit.ac.in",
    "https://dtu.ac.in",
    "https://vit.ac.in",
    "https://srmist.edu.in",
    "https://amrita.edu",
    "https://manipal.edu",
    "https://daiict.ac.in",
    "https://iiit.ac.in",
    "https://jnu.ac.in",
    "https://du.ac.in",
    "https://nirmauni.ac.in",
    "https://pdpu.ac.in",
    "https://ldrp.ac.in",

    # ── INTERNATIONAL UNIVERSITIES ───────────────────────────────────
    "https://mit.edu",
    "https://stanford.edu",
    "https://harvard.edu",
    "https://berkeley.edu",
    "https://ox.ac.uk",
    "https://cam.ac.uk",
    "https://yale.edu",
    "https://princeton.edu",
    "https://caltech.edu",
    "https://columbia.edu",
    "https://cornell.edu",
    "https://nus.edu.sg",
    "https://unimelb.edu.au",

    # ── UNIVERSITY PORTALS (subdomains with login/portal) ───────────
    "https://portal.charusat.edu.in",
    "https://moodle.iitb.ac.in",
    "https://academics.vit.ac.in",
    "https://library.bits-pilani.ac.in",
    "https://login.du.ac.in",
    "https://webmail.charusat.edu.in",
    "https://erp.charusat.edu.in",

    # ── INDIAN GOVERNMENT WEBSITES ───────────────────────────────────
    "https://india.gov.in",
    "https://mygov.in",
    "https://uidai.gov.in",
    "https://incometax.gov.in",
    "https://pmindia.gov.in",
    "https://portal.india.gov.in",
    "https://epfindia.gov.in",
    "https://services.epfindia.gov.in",
    "https://passportindia.gov.in",
    "https://rbi.org.in",
    "https://irctc.co.in",
    "https://login.irctc.co.in",
    "https://www.npci.org.in",
    "https://sebi.gov.in",
    "https://mca.gov.in",

    # ── INTERNATIONAL GOVERNMENT WEBSITES ───────────────────────────
    "https://gov.uk",
    "https://usa.gov",
    "https://australia.gov.au",
    "https://service.gov.sg",
    "https://canada.ca",

    # ── TECH GIANTS ──────────────────────────────────────────────────
    "https://google.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://amazon.com",

    # ── CORPORATE LOGIN PAGES (legitimate login URLs) ────────────────
    "https://accounts.google.com",
    "https://login.microsoft.com",
    "https://appleid.apple.com",
    "https://signin.aws.amazon.com",
    "https://accounts.linkedin.com",
    "https://login.salesforce.com",

    # ── DEVELOPER PLATFORMS ──────────────────────────────────────────
    "https://github.com",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://stackoverflow.com",
    "https://stackexchange.com",
    "https://npmjs.com",
    "https://pypi.org",
    "https://hub.docker.com",
    "https://kubernetes.io",
    "https://developer.mozilla.org",
    "https://docs.python.org",
    "https://api.github.com",

    # ── CLOUD SERVICES ───────────────────────────────────────────────
    "https://drive.google.com",
    "https://docs.google.com",
    "https://onedrive.live.com",
    "https://icloud.com",
    "https://dropbox.com",
    "https://portal.azure.com",
    "https://console.aws.amazon.com",
    "https://console.cloud.google.com",
    "https://app.netlify.com",
    "https://vercel.com",
    "https://heroku.com",

    # ── MAJOR INDIAN BANKS ───────────────────────────────────────────
    "https://onlinesbi.sbi.co.in",
    "https://www.sbi.co.in",
    "https://netbanking.hdfcbank.com",
    "https://www.hdfcbank.com",
    "https://www.icicibank.com",
    "https://www.axisbank.com",
    "https://www.pnbindia.in",
    "https://www.kotak.com",
    "https://www.yesbank.in",
    "https://www.indusind.com",
    "https://www.unionbankofindia.co.in",
    "https://www.canarabank.com",

    # ── INTERNATIONAL BANKS ──────────────────────────────────────────
    "https://www.chase.com",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://www.hsbc.com",
    "https://www.barclays.co.uk",

    # ── PAYMENT SERVICES ─────────────────────────────────────────────
    "https://paytm.com",
    "https://phonepe.com",
    "https://pay.google.com",
    "https://bhimupi.org.in",
    "https://www.paypal.com",
    "https://razorpay.com",
    "https://stripe.com",

    # ── E-COMMERCE ───────────────────────────────────────────────────
    "https://amazon.in",
    "https://flipkart.com",
    "https://myntra.com",
    "https://snapdeal.com",
    "https://ebay.com",
    "https://meesho.com",
    "https://nykaa.com",

    # ── SOCIAL MEDIA ─────────────────────────────────────────────────
    "https://facebook.com",
    "https://twitter.com",
    "https://linkedin.com",
    "https://instagram.com",
    "https://m.facebook.com",
    "https://pinterest.com",

    # ── EMAIL SERVICES ───────────────────────────────────────────────
    "https://gmail.com",
    "https://mail.google.com",
    "https://outlook.com",
    "https://mail.yahoo.com",
    "https://protonmail.com",

    # ── COMMUNICATION & COLLABORATION ────────────────────────────────
    "https://zoom.us",
    "https://slack.com",
    "https://teams.microsoft.com",
    "https://meet.google.com",
    "https://web.whatsapp.com",
    "https://telegram.org",
    "https://discord.com",

    # ── STREAMING & ENTERTAINMENT ────────────────────────────────────
    "https://youtube.com",
    "https://netflix.com",
    "https://spotify.com",
    "https://twitch.tv",
    "https://hotstar.com",
    "https://primevideo.com",

    # ── NEWS & MEDIA ─────────────────────────────────────────────────
    "https://bbc.co.uk",
    "https://reuters.com",
    "https://timesofindia.indiatimes.com",
    "https://ndtv.com",
    "https://thehindu.com",
    "https://hindustantimes.com",

    # ── EDUCATION / LEARNING ─────────────────────────────────────────
    "https://coursera.org",
    "https://udemy.com",
    "https://edx.org",
    "https://khanacademy.org",
    "https://duolingo.com",
    "https://udacity.com",
    "https://nptel.ac.in",

    # ── NON-PROFIT & OPEN SOURCE ─────────────────────────────────────
    "https://wikipedia.org",
    "https://wikimedia.org",
    "https://mozilla.org",
    "https://w3.org",
    "https://ietf.org",
    "https://archive.org",
    "https://creativecommons.org",

    # ── CDNs & INFRASTRUCTURE ────────────────────────────────────────
    "https://cloudflare.com",
    "https://cdn.jsdelivr.net",
    "https://unpkg.com",
    "https://cdnjs.cloudflare.com",

    # ── HEALTHCARE ───────────────────────────────────────────────────
    "https://mohfw.gov.in",
    "https://cowin.gov.in",
    "https://practo.com",
    "https://apollohospitals.com",

    # ── LONG LEGITIMATE URLs (parameters, tracking, sharing) ─────────
    "https://www.google.com/search?q=phishing+detection&oq=phishing&aqs=chrome",
    "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit?usp=sharing",
    "https://www.amazon.in/s?k=laptop&ref=nb_sb_noss_2&_encoding=UTF8&tag=googhydrabk1-21",
    "https://www.flipkart.com/search?q=mobile+phone&otracker=search&marketplace=FLIPKART",
    "https://portal.charusat.edu.in/student/login?redirect=/dashboard&session=active",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstley",

    # ── LEGITIMATE SUBDOMAINS ─────────────────────────────────────────
    "https://mail.google.com",
    "https://static.cloudflare.com",
    "https://secure.login.gov.in",
    "https://portal.sbi.co.in",
    "https://api.twitter.com",
    "https://cdn.example.org",
    "https://support.microsoft.com",
    "https://help.github.com",
]


# ============================================================================
# PHISHING URLS — Known Patterns (30+ URLs)
# ============================================================================

PHISHING_URLS = [

    # ── IP-BASED URLs ────────────────────────────────────────────────
    "http://192.168.1.100/login",
    "http://203.45.67.89/verify-account",
    "http://172.16.0.1/update-payment",
    "http://10.0.0.1/bank/secure",

    # ── SUSPICIOUS KEYWORDS + FREE/SUSPICIOUS TLDs ───────────────────
    "http://paypal-verify-account.tk",
    "http://apple-id-locked.ml",
    "http://netflix-payment-update.ga",
    "http://amazon-security-alert.cf",
    "http://bank-account-suspended.tk",
    "http://secure-verify-account-update-payment-information-required.tk/login",
    "http://free-bank-account.com/login",
    "http://credit-card-approval.xyz/apply",
    "http://netbanking-login.info/verify",

    # ── TYPOSQUATTING ────────────────────────────────────────────────
    "http://gooogle.com/login",
    "http://microosft.com/update",
    "http://faceb00k.com/verify",
    "http://paypa1.com/confirm",
    "http://arnazon.com/signin",
    "http://g00gle.com/accounts",
    "http://linkedln.com/login",

    # ── @ SYMBOL REDIRECTION ─────────────────────────────────────────
    "http://paypal.com@evil-site.com/login",
    "http://sbi.co.in@phishing-domain.xyz/netbanking",

    # ── FREE HOSTING PHISHING ────────────────────────────────────────
    "http://phishing-site.000webhostapp.com",
    "http://fake-bank.wixsite.com/login",
    "http://sbi-netbanking.weebly.com/secure",
    "http://hdfc-login.blogspot.com/verify",

    # ── EXCESSIVE SUBDOMAINS (subdomain stacking) ────────────────────
    "http://login.verify.secure.account.paypal.suspicious.com",
    "http://secure.update.verify.sbi.co.in.evil.xyz/login",

    # ── SUSPICIOUS PATTERNS ──────────────────────────────────────────
    "http://secure-banking.tk/login",
    "http://verify-account.ml/update",
    "http://urgent-action.ga/confirm",
    "http://account-suspended-alert.cf/restore",
    "http://unusual-signin-activity.tk/verify",

    # ── DATA HARVESTING PATTERNS ─────────────────────────────────────
    "http://update-your-kyc-now.xyz/form",
    "http://win-iphone-prize.ml/claim",
    "http://lottery-winner-india.tk/redeem",
]


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def add_urls_to_dataset(csv_path: str):
    """Load existing dataset (or create new), append all URLs, save."""

    # Load or create dataset
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        print(f"  ✓ Loaded existing dataset — {len(df)} URLs")
    else:
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        df = pd.DataFrame(columns=["url", "label"])
        print("  ✗ No existing dataset found — creating new one")

    existing_urls = set(df["url"].tolist())

    # Collect new entries
    new_legitimate = [
        {"url": url, "label": 0}
        for url in LEGITIMATE_URLS
        if url not in existing_urls
    ]
    new_phishing = [
        {"url": url, "label": 1}
        for url in PHISHING_URLS
        if url not in existing_urls
    ]

    new_entries = new_legitimate + new_phishing

    if new_entries:
        df = pd.concat([df, pd.DataFrame(new_entries)], ignore_index=True)
        print(f"  ✓ Added {len(new_legitimate)} new legitimate URLs")
        print(f"  ✓ Added {len(new_phishing)} new phishing URLs")
    else:
        print("  ✓ All URLs already present in dataset — nothing added")

    # Remove duplicates
    before = len(df)
    df = df.drop_duplicates(subset=["url"])
    removed = before - len(df)
    if removed:
        print(f"  ✓ Removed {removed} duplicate(s)")

    # Save
    df.to_csv(csv_path, index=False)

    # Summary
    total      = len(df)
    n_legit    = len(df[df["label"] == 0])
    n_phishing = len(df[df["label"] == 1])

    print(f"\n{'='*60}")
    print(f"  FINAL DATASET STATISTICS")
    print(f"{'='*60}")
    print(f"  Total URLs  : {total}")
    print(f"  Legitimate  : {n_legit}  ({n_legit/total*100:.1f}%)")
    print(f"  Phishing    : {n_phishing}  ({n_phishing/total*100:.1f}%)")
    print(f"  Saved to    : {csv_path}")
    print(f"{'='*60}")

    return df


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_PATH = os.path.join(BASE_DIR, "data", "sample_urls.csv")

    print("=" * 60)
    print("  COMPREHENSIVE URL DATASET BUILDER")
    print("=" * 60)
    print("\n  Scenarios covered:")
    print("    ✓ Educational institutions  (.edu, .ac.in, etc.)")
    print("    ✓ Government websites       (.gov, .gov.in, etc.)")
    print("    ✓ Corporate login pages     (Google, Microsoft, etc.)")
    print("    ✓ Indian & global banks     (SBI, HDFC, Chase, etc.)")
    print("    ✓ E-commerce platforms      (Amazon, Flipkart, etc.)")
    print("    ✓ Cloud services & CDNs     (Drive, Azure, etc.)")
    print("    ✓ Developer platforms       (GitHub, PyPI, etc.)")
    print("    ✓ Long URLs with parameters (Docs, Search, etc.)")
    print("    ✓ Legitimate subdomains     (mail., portal., api., etc.)")
    print("    ✓ International domains     (.uk, .au, .sg, etc.)")
    print("    ✓ Non-profit organisations  (.org, .ngo, etc.)")
    print("    ✓ News & media outlets")
    print("    ✓ Healthcare portals")
    print()

    add_urls_to_dataset(DATA_PATH)

    print("\n  Next steps:")
    print("    1. Train the model  →  python ai/train_model.py")
    print("    2. Start backend    →  python backend/app.py")
    print("    3. Reload extension →  chrome://extensions/")
    print("=" * 60)