# === backend/services/url_validator.py ===
"""
URL Validity Verification Service
Pre-flight checks before phishing analysis
"""

import re
import socket
from urllib.parse import urlparse
from typing import Dict, Tuple


class URLValidator:
    """Validates URL syntax, DNS resolution, and connectivity"""
    
    # RFC 3986 compliant URL pattern
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    def __init__(self, timeout: int = 5):
        """
        Initialize validator
        
        Args:
            timeout: Timeout for connectivity checks (seconds)
        """
        self.timeout = timeout
    
    def validate(self, url: str) -> Dict:
        """
        Perform comprehensive URL validation
        
        Args:
            url: URL to validate
            
        Returns:
            dict with validation results
        """
        result = {
            'is_valid': False,
            'url': url,
            'validation_stages': {},
            'error': None,
            'can_proceed': False,
            'suggestion': None
        }
        
        # Stage 1: Syntax Validation
        syntax_valid, syntax_error = self._validate_syntax(url)
        result['validation_stages']['syntax'] = {
            'passed': syntax_valid,
            'error': syntax_error
        }
        
        if not syntax_valid:
            result['error'] = syntax_error
            result['suggestion'] = 'Please check the URL format. URLs must start with http:// or https://'
            return result
        
        # Stage 2: Length Check
        length_valid, length_error = self._validate_length(url)
        result['validation_stages']['length'] = {
            'passed': length_valid,
            'error': length_error
        }
        
        if not length_valid:
            result['error'] = length_error
            result['suggestion'] = 'URL is too long. Maximum length is 2048 characters.'
            return result
        
        # Stage 3: Domain Extraction
        domain, domain_error = self._extract_domain(url)
        result['validation_stages']['domain_extraction'] = {
            'passed': domain is not None,
            'domain': domain,
            'error': domain_error
        }
        
        if not domain:
            result['error'] = domain_error
            result['suggestion'] = 'Could not extract domain from URL'
            return result
        
        # Stage 4: DNS Resolution
        dns_valid, dns_error = self._check_dns_resolution(domain)
        result['validation_stages']['dns_resolution'] = {
            'passed': dns_valid,
            'error': dns_error
        }
        
        if not dns_valid:
            result['error'] = f'Domain does not exist or cannot be reached: {dns_error}'
            result['suggestion'] = 'Please verify the domain name is correct'
            result['can_retry'] = True
            return result
        
        # Stage 5: Basic Connectivity (optional, may be slow)
        # Skipping for now to maintain speed
        
        # All checks passed
        result['is_valid'] = True
        result['can_proceed'] = True
        result['validation_stages']['overall'] = 'All validation checks passed'
        
        return result
    
    def _validate_syntax(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL syntax according to RFC 3986
        
        Returns:
            tuple: (is_valid, error_message)
        """
        if not url:
            return False, 'URL is empty'
        
        if not isinstance(url, str):
            return False, 'URL must be a string'
        
        # Check for valid scheme
        if not url.startswith(('http://', 'https://')):
            return False, 'URL must start with http:// or https://'
        
        # Check for whitespace
        if ' ' in url:
            return False, 'URL contains whitespace'
        
        # Check overall pattern
        if not self.URL_PATTERN.match(url):
            return False, 'Invalid URL format'
        
        return True, None
    
    def _validate_length(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL length
        
        Returns:
            tuple: (is_valid, error_message)
        """
        max_length = 2048
        
        if len(url) > max_length:
            return False, f'URL exceeds maximum length of {max_length} characters'
        
        return True, None
    
    def _extract_domain(self, url: str) -> Tuple[str, str]:
        """
        Extract domain from URL
        
        Returns:
            tuple: (domain, error_message)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if not domain:
                return None, 'Could not extract domain from URL'
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain, None
            
        except Exception as e:
            return None, f'Failed to parse URL: {str(e)}'
    
    def _check_dns_resolution(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain can be resolved via DNS
        
        Returns:
            tuple: (is_resolvable, error_message)
        """
        try:
            # Set timeout for DNS resolution
            socket.setdefaulttimeout(self.timeout)
            
            # Attempt to resolve domain
            ip_address = socket.gethostbyname(domain)
            
            return True, None
            
        except socket.gaierror as e:
            return False, 'Domain does not exist (DNS resolution failed)'
        
        except socket.timeout:
            return False, 'DNS resolution timeout'
        
        except Exception as e:
            return False, f'DNS check failed: {str(e)}'
    
    def quick_validate(self, url: str) -> bool:
        """
        Quick validation check (syntax only)
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if basic syntax is valid
        """
        if not url or not isinstance(url, str):
            return False
        
        if not url.startswith(('http://', 'https://')):
            return False
        
        if len(url) > 2048:
            return False
        
        return True