// Configuration - Whitelist Only

const CONFIG = {
  // Backend API endpoint
  API_URL: 'http://127.0.0.1:5000/api/scan',
  
  // Cache duration (15 minutes)
  CACHE_TTL_MS: 15 * 60 * 1000,
  
  // Request timeout
  REQUEST_TIMEOUT_MS: 10000,
  
  // Whitelist - Skip API calls for these domains
  WHITELIST: [
    // Development
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    
    // Indian Universities
    'charusat.edu.in',
    'charusat.ac.in',
    'iitb.ac.in',
    'iitd.ac.in',
    'iitm.ac.in',
    'iitk.ac.in',
    'iisc.ac.in',
    'bits-pilani.ac.in',
    'dtu.ac.in',
    'vit.ac.in',
    
    // Indian Government
    'india.gov.in',
    'mygov.in',
    'uidai.gov.in',
    'incometax.gov.in',
    'rbi.org.in',
    'irctc.co.in',
    
    // Indian Banks
    'sbi.co.in',
    'hdfcbank.com',
    'icicibank.com',
    'axisbank.com',
    
    // Global Tech
    'google.com',
    'youtube.com',
    'github.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'facebook.com',
    'twitter.com',
    'linkedin.com',
    'instagram.com',
    'wikipedia.org',
    'cloudflare.com',
    'mozilla.org'
  ]
};

// Export for ES modules
export default CONFIG;