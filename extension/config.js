// Extension Configuration
const CONFIG = {
  // Backend API endpoint - UPDATED TO CORRECT ENDPOINT
  API_URL: 'http://localhost:5000/api/scan',
  
  // Detection thresholds
  CONFIDENCE_THRESHOLD: 0.7,
  HIGH_RISK_THRESHOLD: 0.8,
  
  // Features
  ENABLE_WHATSAPP_PROTECTION: true,
  ENABLE_UNIVERSAL_PROTECTION: true,
  
  // UI Settings
  SHOW_NOTIFICATIONS: true,
  AUTO_BLOCK_HIGH_RISK: false,
  
  // Cache settings
  CACHE_DURATION: 3600000,  // 1 hour in milliseconds
  
  // Whitelist domains (always allow)
  WHITELIST: [
    'google.com',
    'youtube.com',
    'github.com',
    'stackoverflow.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'facebook.com',
    'twitter.com',
    'linkedin.com',
    'instagram.com',
    'reddit.com',
    'wikipedia.org'
  ],
  
  // Performance
  REQUEST_TIMEOUT: 5000,  // 5 seconds
  MAX_RETRIES: 2
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CONFIG;
}