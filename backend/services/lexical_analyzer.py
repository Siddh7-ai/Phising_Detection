# === backend/services/lexical_analyzer.py ===
"""
URL Lexical Analyzer
Analyzes URL structure, patterns, and anomalies

PATCH v1.1 - UUID & Path Intelligence
- Added UUID pattern detection
- Improved domain vs path differentiation
- Added trusted domain whitelist
- Reduced false positives for legitimate URLs
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter


class URLLexicalAnalyzer:
    """Analyzes URL structure for phishing indicators"""
    
    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
    
    # Homoglyph characters (lookalike characters)
    HOMOGLYPHS = {
        '0': ['O', 'o'],
        '1': ['l', 'I', 'i'],
        'a': ['@'],
        'e': ['3'],
        'o': ['0'],
        's': ['5', '$'],
        'g': ['9']
    }
    
    # NEW: Trusted domains whitelist (reduces false positives)
    TRUSTED_DOMAINS = [
        'claude.ai', 'openai.com', 'anthropic.com', 'google.com', 'youtube.com',
        'github.com', 'stackoverflow.com', 'microsoft.com', 'apple.com', 
        'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
        'netflix.com', 'reddit.com', 'wikipedia.org'
    ]
    
    # NEW: UUID pattern (common in modern web apps)
    UUID_PATTERN = re.compile(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', re.IGNORECASE)
    
    def analyze(self, url: str) -> dict:
        """
        Perform lexical analysis on URL
        
        Returns:
            dict with risk_score (0-1) and flags
        """
        flags = []
        risk_score = 0.0
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # NEW: Check if domain is trusted (early exit for known-good domains)
        is_trusted = self._is_trusted_domain(domain)
        
        # NEW: Detect UUID in URL path
        has_uuid_in_path = bool(self.UUID_PATTERN.search(path))
        
        # 1. URL Length Analysis (IMPROVED: more lenient for trusted domains)
        url_length = len(url)
        if url_length > 150:  # Raised from 100 to 150
            if not is_trusted:
                flags.append('Extremely long URL')
                risk_score += 0.20
        elif url_length > 100:  # Raised from 75 to 100
            if not is_trusted:
                flags.append('Long URL')
                risk_score += 0.05  # Reduced from 0.10
        
        # 2. Domain Length
        if len(domain) > 50:
            flags.append('Unusually long domain')
            risk_score += 0.15
        
        # 3. Subdomain Analysis
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            flags.append(f'Multiple subdomains ({subdomain_count})')
            risk_score += 0.15
        
        # 4. Entropy Analysis (randomness) - ONLY on domain, not path
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            # IMPROVED: Don't penalize if domain is trusted
            if not is_trusted:
                flags.append(f'High entropy in domain (possible random string)')
                risk_score += 0.20
        
        # 5. Special Character Density (IMPROVED: only check domain)
        special_chars = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        if special_chars > 3:
            flags.append('Many special characters in domain')
            risk_score += 0.15
        
        # 6. Digit Ratio in Domain
        digits = sum(c.isdigit() for c in domain)
        if digits > len(domain) * 0.3 and len(domain) > 5:
            flags.append('High digit ratio in domain')
            risk_score += 0.10
        
        # 7. Suspicious TLD Check
        for tld in self.SUSPICIOUS_TLDS:
            if url.endswith(tld):
                flags.append(f'Suspicious TLD: {tld}')
                risk_score += 0.25
                break
        
        # 8. IP Address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            flags.append('IP address used instead of domain')
            risk_score += 0.30
        
        # 9. Homoglyph Detection
        if self._contains_homoglyphs(domain):
            flags.append('Possible homoglyph attack (lookalike characters)')
            risk_score += 0.20
        
        # 10. Excessive Hyphens
        if domain.count('-') > 3:
            flags.append('Excessive hyphens in domain')
            risk_score += 0.10
        
        # 11. @ Symbol (credential phishing)
        if '@' in url:
            flags.append('@ symbol in URL (credential hiding)')
            risk_score += 0.30
        
        # 12. Double Slashes in Path
        if '//' in path:
            flags.append('Double slashes in path')
            risk_score += 0.10
        
        # 13. Port Number (non-standard)
        if ':' in parsed.netloc and parsed.netloc.count(':') > 0:
            try:
                port = parsed.netloc.split(':')[-1]
                if port.isdigit() and int(port) not in [80, 443]:
                    flags.append(f'Non-standard port: {port}')
                    risk_score += 0.10
            except:
                pass
        
        # NEW: Trust adjustment (apply small reduction if domain is trusted)
        if is_trusted and risk_score > 0:
            original_score = risk_score
            risk_score = risk_score * 0.5  # 50% reduction for trusted domains
            flags.append(f'Trust adjustment applied (trusted domain detected)')
        
        # NEW: UUID adjustment (reduce suspicion for legitimate session IDs)
        if has_uuid_in_path and risk_score > 0:
            original_score = risk_score
            risk_score = risk_score * 0.8  # 20% reduction for UUID patterns
            # Don't add flag - this is normal behavior
        
        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)
        
        return {
            'risk_score': round(risk_score, 4),
            'flags': flags,
            'metrics': {
                'url_length': url_length,
                'domain_length': len(domain),
                'subdomain_count': subdomain_count,
                'entropy': round(entropy, 2),
                'special_char_count': special_chars,
                'digit_count': digits,
                'is_trusted_domain': is_trusted,  # NEW
                'has_uuid_pattern': has_uuid_in_path  # NEW
            }
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _contains_homoglyphs(self, domain: str) -> bool:
        """Check for potential homoglyph attacks"""
        # Check for common brand names with potential homoglyphs
        common_brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 
                        'apple', 'netflix', 'ebay', 'twitter']
        
        domain_lower = domain.lower()
        
        for brand in common_brands:
            # If domain contains brand name, check for character substitutions
            if brand in domain_lower:
                for real_char, fake_chars in self.HOMOGLYPHS.items():
                    if real_char in brand:
                        for fake in fake_chars:
                            suspicious_variant = brand.replace(real_char, fake.lower())
                            if suspicious_variant in domain_lower and suspicious_variant != brand:
                                return True
        
        return False
    
    def _is_trusted_domain(self, domain: str) -> bool:
        """
        NEW METHOD: Check if domain is in trusted whitelist
        
        Args:
            domain: Domain to check (e.g., 'claude.ai' or 'chat.claude.ai')
            
        Returns:
            bool: True if domain is trusted
        """
        domain_lower = domain.lower()
        
        # Remove port if present
        if ':' in domain_lower:
            domain_lower = domain_lower.split(':')[0]
        
        # Check exact match and subdomain match
        for trusted in self.TRUSTED_DOMAINS:
            if domain_lower == trusted or domain_lower.endswith('.' + trusted):
                return True
        
        return False