# === backend/services/domain_reputation.py ===
"""
Domain Reputation Checker
Validates domain age, DNS records, and blacklist status
"""

import socket
import re
from urllib.parse import urlparse
from datetime import datetime


class DomainReputationChecker:
    """Checks domain reputation and legitimacy signals"""
    
    # Known malicious/suspicious patterns
    PHISHING_PATTERNS = [
        r'verify.*account',
        r'secure.*update',
        r'confirm.*identity',
        r'suspend.*account',
        r'unusual.*activity',
        r'click.*here',
        r'urgent.*action'
    ]
    
    # Known safe domains (whitelist)
    TRUSTED_DOMAINS = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
        'apple.com', 'github.com', 'stackoverflow.com', 'reddit.com',
        'wikipedia.org', 'netflix.com'
    ]
    
    def check(self, url: str) -> dict:
        """
        Check domain reputation
        
        Returns:
            dict with risk_score (0-1) and checks performed
        """
        risk_score = 0.0
        checks = {}
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 1. Trusted Domain Check
        checks['is_trusted'] = self._is_trusted_domain(domain)
        if checks['is_trusted']:
            risk_score = 0.0  # Override - trusted domain
            checks['trusted_match'] = domain
            return {
                'risk_score': 0.0,
                'checks': checks
            }
        
        # 2. DNS Resolution Check
        checks['dns_resolvable'] = self._check_dns_resolution(domain)
        if not checks['dns_resolvable']:
            risk_score += 0.40
            checks['dns_status'] = 'Failed to resolve'
        else:
            checks['dns_status'] = 'Resolved successfully'
        
        # 3. Domain Age Estimation (heuristic)
        domain_age_risk = self._estimate_domain_age_risk(domain)
        checks['domain_age_risk'] = domain_age_risk
        risk_score += domain_age_risk
        
        # 4. Phishing Pattern Detection
        phishing_patterns_found = self._check_phishing_patterns(url)
        checks['phishing_patterns'] = phishing_patterns_found
        if phishing_patterns_found:
            risk_score += 0.25
        
        # 5. SSL/TLS Check (HTTPS)
        checks['uses_https'] = parsed.scheme == 'https'
        if not checks['uses_https']:
            risk_score += 0.15
        
        # 6. Brand Impersonation Check
        impersonation_risk = self._check_brand_impersonation(domain)
        checks['brand_impersonation_risk'] = impersonation_risk
        risk_score += impersonation_risk
        
        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        
        return {
            'risk_score': round(risk_score, 4),
            'checks': checks
        }
    
    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain is in trusted list"""
        for trusted in self.TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return True
        return False
    
    def _check_dns_resolution(self, domain: str) -> bool:
        """Check if domain can be resolved via DNS"""
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
        except Exception:
            return True  # Assume resolvable if other error
    
    def _estimate_domain_age_risk(self, domain: str) -> float:
        """
        Heuristic domain age estimation
        New domains are higher risk for phishing
        """
        # Very simple heuristic: check for numbers at end (often used in new phishing domains)
        if re.search(r'\d{3,}', domain):
            return 0.20  # Numbers suggest possible temporary/new domain
        
        # Check for year patterns that might indicate new registration
        current_year = datetime.now().year
        if str(current_year) in domain or str(current_year - 1) in domain:
            return 0.15
        
        return 0.0  # Can't determine, assume neutral
    
    def _check_phishing_patterns(self, url: str) -> list:
        """Check for common phishing URL patterns"""
        url_lower = url.lower()
        found_patterns = []
        
        for pattern in self.PHISHING_PATTERNS:
            if re.search(pattern, url_lower):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _check_brand_impersonation(self, domain: str) -> float:
        """
        Check for brand impersonation attempts
        e.g., paypa1.com instead of paypal.com
        """
        risk = 0.0
        domain_lower = domain.lower()
        
        # Common brands
        brands = {
            'paypal': ['paypa1', 'paypai', 'paypa|', 'paypa'],
            'amazon': ['amaz0n', 'amazom', 'arnazon'],
            'google': ['goog1e', 'gooogle', 'googie'],
            'facebook': ['faceb00k', 'facebok', 'faceboook'],
            'microsoft': ['micros0ft', 'microsft', 'rnicrosoft'],
            'apple': ['app1e', 'appl3', 'appie'],
            'netflix': ['netf1ix', 'netfiix', 'netfIix']
        }
        
        for brand, variants in brands.items():
            # Check if legitimate brand in domain
            if brand in domain_lower:
                # Check if it's exactly the brand (legitimate)
                if domain_lower == brand + '.com' or f'.{brand}.com' in domain_lower:
                    continue  # Legitimate
                else:
                    # Brand appears but not in legitimate position
                    risk += 0.20
                    break
            
            # Check for common typosquatting variants
            for variant in variants:
                if variant in domain_lower:
                    risk += 0.30
                    break
        
        return min(risk, 0.30)  # Cap contribution