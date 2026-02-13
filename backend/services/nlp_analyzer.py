# === backend/services/nlp_analyzer.py ===
"""
NLP-Based Phishing Language Analyzer
Detects social engineering and urgency tactics in URLs and content
"""

import re
from urllib.parse import urlparse, unquote


class NLPPhishingAnalyzer:
    """Analyzes URL and text for phishing language patterns"""
    
    # Urgency keywords (create panic)
    URGENCY_KEYWORDS = [
        'urgent', 'immediately', 'asap', 'expire', 'expires', 'expired',
        'limited', 'hurry', 'act now', 'quick', 'fast', 'deadline',
        'suspend', 'suspended', 'lock', 'locked', 'block', 'blocked'
    ]
    
    # Trust exploitation keywords
    TRUST_KEYWORDS = [
        'verify', 'confirm', 'validate', 'update', 'secure', 'protect',
        'alert', 'warning', 'notice', 'important', 'critical', 'attention'
    ]
    
    # Financial keywords (target money/credentials)
    FINANCIAL_KEYWORDS = [
        'account', 'bank', 'credit', 'card', 'payment', 'billing',
        'invoice', 'transaction', 'refund', 'claim', 'reward', 'prize',
        'won', 'winner', 'free', 'bonus', 'cash', 'money'
    ]
    
    # Action keywords (encourage clicking)
    ACTION_KEYWORDS = [
        'click', 'download', 'install', 'open', 'view', 'access',
        'sign in', 'login', 'signin', 'log in', 'enter', 'submit'
    ]
    
    # Brand impersonation indicators
    BRAND_KEYWORDS = [
        'paypal', 'amazon', 'ebay', 'apple', 'microsoft', 'google',
        'facebook', 'netflix', 'bank', 'irs', 'usps', 'fedex', 'dhl'
    ]
    
    def analyze(self, url: str, page_title: str = None, page_text: str = None) -> dict:
        """
        Analyze URL and optional page content for phishing language
        
        Args:
            url: URL to analyze
            page_title: Optional page title
            page_text: Optional page text content
            
        Returns:
            dict with risk_score (0-1) and detected keywords
        """
        risk_score = 0.0
        detected_keywords = {
            'urgency': [],
            'trust': [],
            'financial': [],
            'action': [],
            'brand': []
        }
        
        # Decode URL for analysis
        decoded_url = unquote(url).lower()
        parsed = urlparse(decoded_url)
        
        # Combine all analyzable text
        full_text = decoded_url
        if page_title:
            full_text += ' ' + page_title.lower()
        if page_text:
            full_text += ' ' + page_text.lower()[:500]  # First 500 chars only
        
        # 1. Urgency Detection
        urgency_count = 0
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in full_text:
                detected_keywords['urgency'].append(keyword)
                urgency_count += 1
        
        if urgency_count > 0:
            risk_score += min(urgency_count * 0.08, 0.25)
        
        # 2. Trust Exploitation
        trust_count = 0
        for keyword in self.TRUST_KEYWORDS:
            if keyword in full_text:
                detected_keywords['trust'].append(keyword)
                trust_count += 1
        
        if trust_count > 0:
            risk_score += min(trust_count * 0.06, 0.20)
        
        # 3. Financial Keywords
        financial_count = 0
        for keyword in self.FINANCIAL_KEYWORDS:
            if keyword in full_text:
                detected_keywords['financial'].append(keyword)
                financial_count += 1
        
        if financial_count > 0:
            risk_score += min(financial_count * 0.05, 0.15)
        
        # 4. Action Keywords
        action_count = 0
        for keyword in self.ACTION_KEYWORDS:
            if keyword in full_text:
                detected_keywords['action'].append(keyword)
                action_count += 1
        
        if action_count > 0:
            risk_score += min(action_count * 0.04, 0.15)
        
        # 5. Brand Impersonation
        brand_count = 0
        for keyword in self.BRAND_KEYWORDS:
            if keyword in full_text:
                detected_keywords['brand'].append(keyword)
                brand_count += 1
        
        if brand_count > 0:
            # Brand mentions increase risk especially with urgency/trust words
            if urgency_count > 0 or trust_count > 0:
                risk_score += 0.20
            else:
                risk_score += 0.10
        
        # 6. Combined Pattern Detection (High Risk)
        # Urgency + Financial + Action = Classic phishing
        if urgency_count > 0 and financial_count > 0 and action_count > 0:
            risk_score += 0.25
            detected_keywords['pattern'] = 'Urgency + Financial + Action (High Risk)'
        
        # Brand + Verify/Confirm + Urgency = Brand impersonation phishing
        if brand_count > 0 and trust_count > 0 and urgency_count > 0:
            risk_score += 0.30
            detected_keywords['pattern'] = 'Brand Impersonation + Urgency (Very High Risk)'
        
        # 7. Suspicious Phrases (regex patterns)
        suspicious_phrases = [
            r'verify.*account',
            r'confirm.*identity',
            r'unusual.*activity',
            r'suspend.*account',
            r'update.*payment',
            r'claim.*prize',
            r'won.*\$',
            r'act.*now',
            r'limited.*time',
            r'click.*here.*(?:verify|confirm|update)'
        ]
        
        phrases_found = []
        for pattern in suspicious_phrases:
            if re.search(pattern, full_text):
                phrases_found.append(pattern)
        
        if phrases_found:
            risk_score += min(len(phrases_found) * 0.10, 0.30)
            detected_keywords['suspicious_phrases'] = phrases_found
        
        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        
        # Remove duplicates and limit
        for category in detected_keywords:
            if isinstance(detected_keywords[category], list):
                detected_keywords[category] = list(set(detected_keywords[category]))[:5]
        
        return {
            'risk_score': round(risk_score, 4),
            'keywords': detected_keywords,
            'analysis_summary': self._generate_summary(detected_keywords, risk_score)
        }
    
    def _generate_summary(self, keywords: dict, risk_score: float) -> str:
        """Generate human-readable summary of NLP analysis"""
        if risk_score >= 0.7:
            return 'High-risk language patterns detected: strong indicators of phishing attempt'
        elif risk_score >= 0.4:
            return 'Suspicious language patterns found: exercise caution'
        elif risk_score >= 0.2:
            return 'Some concerning language elements present'
        else:
            return 'No significant phishing language patterns detected'