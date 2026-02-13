# === backend/services/html_behavior_analyzer.py ===
"""
HTML & JavaScript Behavior Analyzer
Analyzes webpage structure for phishing indicators
"""

import re
from urllib.parse import urlparse


class HTMLBehaviorAnalyzer:
    """Analyzes HTML/JS behavior patterns typical of phishing sites"""
    
    # Suspicious JavaScript patterns
    SUSPICIOUS_JS_PATTERNS = [
        r'eval\s*\(',
        r'document\.write\s*\(',
        r'window\.location\s*=',
        r'fromCharCode',
        r'unescape\s*\(',
        r'iframe.*hidden',
        r'onclick\s*=\s*["\'].*redirect'
    ]
    
    # Suspicious form patterns
    SUSPICIOUS_FORM_PATTERNS = [
        r'<input[^>]*type\s*=\s*["\']password["\']',
        r'<form[^>]*action\s*=\s*["\']https?://(?!{domain})',
        r'<input[^>]*name\s*=\s*["\'](?:cc|cvv|card)',
        r'<input[^>]*(?:ssn|social)'
    ]
    
    def analyze(self, url: str) -> dict:
        """
        Analyze URL for suspicious HTML/JS behavior patterns
        
        NOTE: This is a lightweight version that analyzes URL structure
        Full implementation would fetch and parse actual HTML content
        
        Returns:
            dict with risk_score (0-1) and findings
        """
        risk_score = 0.0
        findings = []
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # 1. Suspicious Path Analysis
        suspicious_paths = ['login', 'signin', 'verify', 'confirm', 'update', 'secure']
        path_matches = [p for p in suspicious_paths if p in path]
        if path_matches:
            findings.append(f'Suspicious path elements: {", ".join(path_matches)}')
            risk_score += 0.10 * len(path_matches)
        
        # 2. Query Parameter Analysis
        suspicious_params = ['redirect', 'return', 'continue', 'next', 'url', 'goto']
        param_matches = [p for p in suspicious_params if p in query]
        if param_matches:
            findings.append(f'Suspicious query parameters: {", ".join(param_matches)}')
            risk_score += 0.15
        
        # 3. Encoded Characters in URL (obfuscation)
        if '%' in url:
            percent_count = url.count('%')
            if percent_count > 5:
                findings.append(f'Heavy URL encoding detected ({percent_count} encoded chars)')
                risk_score += 0.15
        
        # 4. JavaScript in URL
        if 'javascript:' in url.lower():
            findings.append('JavaScript protocol in URL')
            risk_score += 0.30
        
        # 5. Data URLs (can hide content)
        if url.lower().startswith('data:'):
            findings.append('Data URL detected (can hide malicious content)')
            risk_score += 0.25
        
        # 6. Multiple Redirects Indication
        if query.count('http') > 1:
            findings.append('Multiple URLs in query (possible redirect chain)')
            risk_score += 0.20
        
        # 7. Suspicious File Extensions
        suspicious_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.cmd', '.vbs']
        for ext in suspicious_extensions:
            if ext in path:
                findings.append(f'Suspicious file extension: {ext}')
                risk_score += 0.25
                break
        
        # 8. Form-related Keywords in Path
        form_keywords = ['submit', 'post', 'form', 'input']
        form_matches = [k for k in form_keywords if k in path]
        if form_matches:
            findings.append(f'Form-related path elements: {", ".join(form_matches)}')
            risk_score += 0.10
        
        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        
        return {
            'risk_score': round(risk_score, 4),
            'findings': findings,
            'analysis_note': 'URL-based heuristic analysis (full HTML parsing not performed)'
        }
    
    def analyze_html_content(self, html_content: str, url: str) -> dict:
        """
        ADVANCED: Analyze actual HTML content
        This method would be called if HTML is fetched
        
        Args:
            html_content: Raw HTML content
            url: Original URL
            
        Returns:
            dict with detailed behavior analysis
        """
        risk_score = 0.0
        findings = []
        
        html_lower = html_content.lower()
        
        # 1. Check for suspicious JavaScript
        js_matches = 0
        for pattern in self.SUSPICIOUS_JS_PATTERNS:
            if re.search(pattern, html_lower):
                js_matches += 1
        
        if js_matches > 0:
            findings.append(f'Suspicious JavaScript patterns found ({js_matches})')
            risk_score += min(js_matches * 0.10, 0.30)
        
        # 2. Hidden iframes
        if 'iframe' in html_lower:
            hidden_iframe_patterns = [
                r'<iframe[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none',
                r'<iframe[^>]*style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden',
                r'<iframe[^>]*width\s*=\s*["\']0["\']',
                r'<iframe[^>]*height\s*=\s*["\']0["\']'
            ]
            for pattern in hidden_iframe_patterns:
                if re.search(pattern, html_lower):
                    findings.append('Hidden iframe detected (can load malicious content)')
                    risk_score += 0.25
                    break
        
        # 3. Form analysis
        if '<form' in html_lower:
            # Check for password fields
            if 'type="password"' in html_lower or "type='password'" in html_lower:
                findings.append('Password input field found')
                risk_score += 0.10
                
                # Check if form submits to external domain
                parsed = urlparse(url)
                current_domain = parsed.netloc
                
                form_action_match = re.search(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', html_lower)
                if form_action_match:
                    action_url = form_action_match.group(1)
                    if action_url.startswith('http'):
                        action_parsed = urlparse(action_url)
                        if action_parsed.netloc != current_domain:
                            findings.append('Form submits to external domain (credential theft risk)')
                            risk_score += 0.30
        
        # 4. Credit card fields
        cc_patterns = [r'cvv', r'card.*number', r'credit.*card', r'expir']
        cc_matches = sum(1 for pattern in cc_patterns if re.search(pattern, html_lower))
        if cc_matches > 2:
            findings.append('Multiple credit card fields detected')
            risk_score += 0.20
        
        # 5. Excessive external scripts
        script_tags = re.findall(r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']', html_lower)
        external_scripts = [s for s in script_tags if s.startswith('http')]
        if len(external_scripts) > 5:
            findings.append(f'Many external scripts loaded ({len(external_scripts)})')
            risk_score += 0.15
        
        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        
        return {
            'risk_score': round(risk_score, 4),
            'findings': findings,
            'metrics': {
                'suspicious_js_patterns': js_matches,
                'external_scripts': len(external_scripts) if external_scripts else 0,
                'has_forms': '<form' in html_lower,
                'has_password_fields': 'type="password"' in html_lower
            }
        }