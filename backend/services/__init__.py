# === backend/services/__init__.py ===
"""
PhishGuard AI - Enhanced Detection Services Module

This module contains advanced detection components for the ensemble detection engine.

Components:
- url_validator: Pre-flight URL validation (Feature 6)
- ensemble_engine: Coordinates all detection modules (Feature 1)
- lexical_analyzer: URL structure analysis
- domain_reputation: Domain verification and reputation checks
- html_behavior_analyzer: Webpage behavior analysis
- nlp_analyzer: Phishing language detection
"""

__version__ = "1.0.0"
__all__ = [
    'URLValidator',
    'EnsembleDetectionEngine',
    'URLLexicalAnalyzer',
    'DomainReputationChecker',
    'HTMLBehaviorAnalyzer',
    'NLPPhishingAnalyzer'
]

# Import all classes for easy access
try:
    from .url_validator import URLValidator
    from .ensemble_engine import EnsembleDetectionEngine
    from .lexical_analyzer import URLLexicalAnalyzer
    from .domain_reputation import DomainReputationChecker
    from .html_behavior_analyzer import HTMLBehaviorAnalyzer
    from .nlp_analyzer import NLPPhishingAnalyzer
except ImportError as e:
    # Graceful degradation if imports fail
    print(f"Warning: Could not import all services modules: {e}")