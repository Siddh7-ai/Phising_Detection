// Background Service Worker - Manifest V3
// Handles URL checking and navigation interception

// Import config
importScripts('config.js');

// Cache for recently checked URLs
const urlCache = new Map();

// Statistics
let stats = {
  totalChecks: 0,
  phishingBlocked: 0,
  lastCheck: null
};

// Load stats from storage
chrome.storage.local.get(['stats'], (result) => {
  if (result.stats) {
    stats = result.stats;
  }
});

/**
 * Check if URL is in whitelist
 */
function isWhitelisted(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    return CONFIG.WHITELIST.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
  } catch {
    return false;
  }
}

/**
 * Check if URL is cached
 */
function getCachedResult(url) {
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
    return cached.result;
  }
  urlCache.delete(url);
  return null;
}

/**
 * Transform API response to internal format
 */
function transformAPIResponse(apiData) {
  // API returns: { classification: "Phishing"/"Legitimate", confidence: 0-100, metrics: {...} }
  const isPhishing = apiData.classification === 'Phishing';
  const confidenceDecimal = apiData.confidence / 100; // Convert 0-100 to 0-1
  
  // Determine risk level
  let riskLevel = 'low';
  if (isPhishing) {
    if (apiData.confidence >= 80) riskLevel = 'high';
    else if (apiData.confidence >= 60) riskLevel = 'medium';
  }
  
  // Build explanation from metrics
  let explanation = '';
  if (isPhishing) {
    const reasons = [];
    if (apiData.metrics.suspicious_keywords) reasons.push('suspicious keywords detected');
    if (!apiData.metrics.https) reasons.push('no HTTPS');
    if (apiData.metrics.has_ip) reasons.push('IP address in URL');
    if (apiData.metrics.url_length > 75) reasons.push('abnormally long URL');
    
    const ageMatch = apiData.metrics.domain_age?.match(/(\d+)/);
    if (ageMatch && parseInt(ageMatch[1]) < 30) reasons.push('very new domain');
    
    explanation = reasons.length > 0 
      ? reasons.join(', ') 
      : 'Multiple phishing indicators detected';
  } else {
    explanation = '✓ No obvious threats detected';
  }
  
  return {
    url: apiData.url,
    is_phishing: isPhishing,
    confidence: confidenceDecimal,
    risk_level: riskLevel,
    explanation: explanation,
    metrics: apiData.metrics,
    model: apiData.model,
    timestamp: apiData.timestamp
  };
}

/**
 * Check URL with backend API
 */
async function checkURL(url) {
  // Check whitelist
  if (isWhitelisted(url)) {
    return {
      url: url,
      is_phishing: false,
      confidence: 1.0,
      risk_level: 'low',
      explanation: '✓ Whitelisted domain',
      from_cache: false
    };
  }
  
  // Check cache
  const cached = getCachedResult(url);
  if (cached) {
    return { ...cached, from_cache: true };
  }
  
  // Call API
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
    
    const response = await fetch(CONFIG.API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const apiData = await response.json();
    
    // Transform to internal format
    const result = transformAPIResponse(apiData);
    
    // Cache result
    urlCache.set(url, {
      result: result,
      timestamp: Date.now()
    });
    
    // Update stats
    stats.totalChecks++;
    if (result.is_phishing) {
      stats.phishingBlocked++;
    }
    stats.lastCheck = new Date().toISOString();
    chrome.storage.local.set({ stats: stats });
    
    return { ...result, from_cache: false };
    
  } catch (error) {
    console.error('URL check error:', error);
    
    // Return safe default on error
    return {
      url: url,
      is_phishing: false,
      confidence: 0.5,
      risk_level: 'unknown',
      explanation: 'Unable to verify URL - proceed with caution',
      error: error.message,
      from_cache: false
    };
  }
}

/**
 * Handle navigation requests
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only check main frame (not iframes)
  if (details.frameId !== 0) return;
  
  // Skip internal pages
  if (details.url.startsWith('chrome://') || 
      details.url.startsWith('chrome-extension://') ||
      details.url.startsWith('about:')) {
    return;
  }
  
  // Skip if universal protection is disabled
  if (!CONFIG.ENABLE_UNIVERSAL_PROTECTION) return;
  
  console.log('Checking URL before navigation:', details.url);
  
  // Check URL
  const result = await checkURL(details.url);
  
  // If phishing detected, show warning
  if (result.is_phishing && result.confidence >= CONFIG.CONFIDENCE_THRESHOLD) {
    // Store result for warning page
    chrome.storage.local.set({ 
      lastDetection: {
        ...result,
        originalUrl: details.url,
        timestamp: Date.now()
      }
    });
    
    // Redirect to warning page
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('warning.html')
    });
  }
});

/**
 * Listen for messages from content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_URL') {
    // Check URL and send result
    checkURL(message.url).then(result => {
      sendResponse(result);
    }).catch(error => {
      sendResponse({
        error: error.message,
        is_phishing: false
      });
    });
    return true;  // Keep channel open for async response
  }
  
  if (message.type === 'GET_STATS') {
    sendResponse(stats);
    return true;
  }
  
  if (message.type === 'RESET_STATS') {
    stats = {
      totalChecks: 0,
      phishingBlocked: 0,
      lastCheck: null
    };
    chrome.storage.local.set({ stats: stats });
    sendResponse({ success: true });
    return true;
  }
});

/**
 * Handle extension icon click
 */
chrome.action.onClicked.addListener((tab) => {
  // Open popup (default behavior)
});

/**
 * Periodic cache cleanup
 */
setInterval(() => {
  const now = Date.now();
  for (const [url, data] of urlCache.entries()) {
    if (now - data.timestamp > CONFIG.CACHE_DURATION) {
      urlCache.delete(url);
    }
  }
}, 300000);  // Every 5 minutes

console.log('🛡️ Phishing Detection Shield - Background service worker loaded');
console.log('Config:', CONFIG);