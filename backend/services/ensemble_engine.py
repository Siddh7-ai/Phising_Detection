"""
Ensemble-Based Phishing Detection Engine
Version: 6.1.1 (SYNTAX FIX)

CHANGES FROM v6.1.0:
- Fixed indentation: fallback methods are now class methods, not nested inside analyze()
- All other scoring logic remains the same
"""

import traceback
from typing import Dict, List


class EnsembleDetectionEngine:
    """
    Coordinates multiple detection modules.
    Final decision is based exclusively on the ML model score.
    All other module scores are included in the response for visualization.
    """
    
    WEIGHTS = {
        'ml_model': 1.00,  # 100% — sole driver of final verdict
        'lexical': 0.00,   # Analytical only
        'reputation': 0.00,  # Analytical only
        'behavior': 0.00,   # Analytical only
        'nlp': 0.00        # Analytical only
    }
    
    PHISHING_THRESHOLD = 0.75
    SUSPICIOUS_THRESHOLD = 0.40
    
    def __init__(self, lexical_analyzer=None, reputation_checker=None, 
                 behavior_analyzer=None, nlp_analyzer=None):
        """Initialize with detection modules."""
        self.lexical_analyzer = lexical_analyzer
        self.reputation_checker = reputation_checker
        self.behavior_analyzer = behavior_analyzer
        self.nlp_analyzer = nlp_analyzer
    
    def analyze(self, url: str, ml_confidence: float, ml_prediction: str, 
                risk_factors: List[str]) -> Dict:
        """
        Run all detection modules and return a unified result.
        Final classification and ensemble_score are based ONLY on ml_confidence.
        Other module scores are returned for frontend analytics / visualization.
        """
        results = {
            'url': url,
            'ml_confidence': ml_confidence,
            'ml_prediction': ml_prediction,
            'ml_risk_factors': risk_factors,
            'ensemble_modules': {},
            'ensemble_score': 0.0,
            'final_classification': 'Unknown',
            'final_risk_level': 'Unknown',
            'detection_breakdown': {}
        }
        
        # ── 1. ML Model (drives the final decision) ──────────────────
        results['ensemble_modules']['ml_model'] = {
            'score': ml_confidence,
            'weight': self.WEIGHTS['ml_model'],
            'status': 'success',
            'note': 'Primary decision driver'
        }
        
        # ── 2. Lexical Analysis (visualization only) ─────────────────
        if self.lexical_analyzer:
            try:
                lexical_result = self.lexical_analyzer.analyze(url)
                results['ensemble_modules']['lexical'] = {
                    'score': lexical_result['risk_score'],
                    'weight': self.WEIGHTS['lexical'],
                    'status': 'success',
                    'details': lexical_result.get('flags', []),
                    'note': 'Analytical only — does not affect verdict'
                }
            except Exception as e:
                results['ensemble_modules']['lexical'] = {
                    'score': self._lexical_fallback(url),
                    'weight': self.WEIGHTS['lexical'],
                    'status': 'fallback',
                    'error': str(e),
                    'note': 'Analytical only — does not affect verdict'
                }
        else:
            results['ensemble_modules']['lexical'] = {
                'score': self._lexical_fallback(url),
                'weight': self.WEIGHTS['lexical'],
                'status': 'inline',
                'note': 'Analytical only — does not affect verdict'
            }
        
        # ── 3. Reputation Check (visualization only) ─────────────────
        if self.reputation_checker:
            try:
                reputation_result = self.reputation_checker.check(url)
                results['ensemble_modules']['reputation'] = {
                    'score': reputation_result['risk_score'],
                    'weight': self.WEIGHTS['reputation'],
                    'status': 'success',
                    'details': reputation_result.get('checks', {}),
                    'note': 'Analytical only — does not affect verdict'
                }
            except Exception as e:
                results['ensemble_modules']['reputation'] = {
                    'score': self._reputation_fallback(url),
                    'weight': self.WEIGHTS['reputation'],
                    'status': 'fallback',
                    'error': str(e),
                    'note': 'Analytical only — does not affect verdict'
                }
        else:
            results['ensemble_modules']['reputation'] = {
                'score': self._reputation_fallback(url),
                'weight': self.WEIGHTS['reputation'],
                'status': 'inline',
                'note': 'Analytical only — does not affect verdict'
            }
        
        # ── 4. Behavior Analysis (visualization only) ────────────────
        if self.behavior_analyzer:
            try:
                behavior_result = self.behavior_analyzer.analyze(url)
                results['ensemble_modules']['behavior'] = {
                    'score': behavior_result['risk_score'],
                    'weight': self.WEIGHTS['behavior'],
                    'status': 'success',
                    'details': behavior_result.get('findings', []),
                    'note': 'Analytical only — does not affect verdict'
                }
            except Exception as e:
                results['ensemble_modules']['behavior'] = {
                    'score': self._behavior_fallback(url),
                    'weight': self.WEIGHTS['behavior'],
                    'status': 'fallback',
                    'error': str(e),
                    'note': 'Analytical only — does not affect verdict'
                }
        else:
            results['ensemble_modules']['behavior'] = {
                'score': self._behavior_fallback(url),
                'weight': self.WEIGHTS['behavior'],
                'status': 'inline',
                'note': 'Analytical only — does not affect verdict'
            }
        
        # ── 5. NLP Analysis (visualization only) ─────────────────────
        if self.nlp_analyzer:
            try:
                nlp_result = self.nlp_analyzer.analyze(url)
                results['ensemble_modules']['nlp'] = {
                    'score': nlp_result['risk_score'],
                    'weight': self.WEIGHTS['nlp'],
                    'status': 'success',
                    'details': nlp_result.get('keywords', []),
                    'note': 'Analytical only — does not affect verdict'
                }
            except Exception as e:
                results['ensemble_modules']['nlp'] = {
                    'score': self._nlp_fallback(url),
                    'weight': self.WEIGHTS['nlp'],
                    'status': 'fallback',
                    'error': str(e),
                    'note': 'Analytical only — does not affect verdict'
                }
        else:
            results['ensemble_modules']['nlp'] = {
                'score': self._nlp_fallback(url),
                'weight': self.WEIGHTS['nlp'],
                'status': 'inline',
                'note': 'Analytical only — does not affect verdict'
            }
        
        # ── Final scoring: ML score only ─────────────────────────────
        final_score = ml_confidence  # sole source of truth
        
        if final_score >= self.PHISHING_THRESHOLD:
            final_classification = 'Phishing'
            final_risk_level = 'High'
        elif final_score >= self.SUSPICIOUS_THRESHOLD:
            final_classification = 'Suspicious'
            final_risk_level = 'Medium'
        else:
            final_classification = 'Legitimate'
            final_risk_level = 'Low'
        
        results['ensemble_score'] = round(final_score, 4)
        results['final_classification'] = final_classification
        results['final_risk_level'] = final_risk_level
        results['confidence_percentage'] = round(final_score * 100, 2)
        results['scoring_policy'] = 'final_score=ml_score (other modules analytical only)'
        
        # detection_breakdown mirrors ensemble_modules for frontend charts
        for module_name, module_data in results['ensemble_modules'].items():
            results['detection_breakdown'][module_name] = {
                'raw_score': module_data['score'],
                'weight': module_data['weight'],
                'contribution': module_data['score'],  # raw for visualization
                'status': module_data['status']
            }
        
        # Add clean module score mapping for frontend
        results['modules'] = {
            'ml': results['ensemble_modules']['ml_model']['score'],
            'lexical': results['ensemble_modules']['lexical']['score'],
            'reputation': results['ensemble_modules']['reputation']['score'],
            'behavior': results['ensemble_modules']['behavior']['score'],
            'nlp': results['ensemble_modules']['nlp']['score']
        }
        
        return results
    
    # ── Inline fallback scorers (PROPERLY INDENTED AS CLASS METHODS) ──
    
    def _lexical_fallback(self, url: str) -> float:
        """Inline lexical scoring — used when URLLexicalAnalyzer is unavailable."""
        import re
        from urllib.parse import urlparse
        
        score = 0.0
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        
        if len(url) > 100:
            score += 0.25
        elif len(url) > 75:
            score += 0.15
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.30
        
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']
        for tld in suspicious_tlds:
            if domain.endswith(tld) or ('.' + tld.lstrip('.') + '.') in domain:
                score += 0.25
                break
        
        if '@' in url:
            score += 0.20
        
        subd = domain.count('.')
        if subd > 3:
            score += 0.10
        elif subd > 2:
            score += 0.05
        
        if domain.count('-') > 3:
            score += 0.10
        elif domain.count('-') > 1:
            score += 0.05
        
        if len(domain) > 40:
            score += 0.10
        
        suspicious_words = ['verify', 'secure', 'account', 'update', 'login', 
                          'signin', 'confirm', 'banking']
        for w in suspicious_words:
            if w in domain:
                score += 0.10
                break
        
        return round(min(score, 1.0), 4)
    
    def _reputation_fallback(self, url: str) -> float:
        """Inline reputation scoring — used when DomainReputationChecker is unavailable."""
        import re
        from urllib.parse import urlparse
        
        score = 0.0
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        
        safe_domains = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 
                       'twitter.com', 'microsoft.com', 'apple.com', 'github.com', 
                       'netflix.com', 'paypal.com']
        
        for safe in safe_domains:
            if domain == safe or domain.endswith('.' + safe):
                return 0.0
        
        if parsed.scheme != 'https':
            score += 0.30
        
        suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 
                          'confirm', 'banking']
        for w in suspicious_words:
            if w in domain:
                score += 0.15
                break
        
        brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 
                 'apple', 'netflix', 'ebay']
        for brand in brands:
            if brand in domain:
                if not (domain == brand + '.com' or domain.endswith('.' + brand + '.com')):
                    score += 0.30
                    break
        
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 0.35
        
        if len(domain) > 40:
            score += 0.10
        
        return round(min(score, 1.0), 4)
    
    def _behavior_fallback(self, url: str) -> float:
        """Inline behavior scoring — used when HTMLBehaviorAnalyzer is unavailable."""
        from urllib.parse import urlparse
        
        score = 0.0
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        for s in shorteners:
            if s in url:
                score += 0.30
                break
        
        special_chars = sum(1 for c in url if c in '-_.~!*\'();:@&=+$,/?#[]')
        if special_chars > 15:
            score += 0.20
        elif special_chars > 8:
            score += 0.10
        
        if '%' in url:
            p = url.count('%')
            if p > 5:
                score += 0.20
            elif p > 2:
                score += 0.10
        
        suspicious_paths = ['login', 'signin', 'verify', 'confirm', 'update', 
                          'secure', 'account', 'banking']
        path_hits = sum(1 for p in suspicious_paths if p in path)
        if path_hits > 0:
            score += min(path_hits * 0.10, 0.25)
        
        redirect_params = ['redirect', 'return', 'continue', 'next', 'url', 'goto']
        if any(p in query for p in redirect_params):
            score += 0.15
        
        if '//' in path:
            score += 0.10
        
        return round(min(score, 1.0), 4)
    
    def _nlp_fallback(self, url: str) -> float:
        """Inline NLP scoring — used when NLPPhishingAnalyzer is unavailable."""
        url_lower = url.lower()
        
        PHISHING_KEYWORDS = ['verify', 'account', 'update', 'confirm', 'login', 
                            'signin', 'banking', 'secure', 'unusual', 'click', 
                            'now', 'immediately', 'urgent', 'password', 
                            'credential', 'credit', 'card']
        URGENCY_KEYWORDS = ['urgent', 'immediately', 'expire', 'expires', 
                           'expired', 'suspend', 'suspended', 'locked', 
                           'blocked', 'limited']
        
        keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
        urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in url_lower)
        
        return round(min(keyword_count * 0.12 + urgency_count * 0.10, 1.0), 4)