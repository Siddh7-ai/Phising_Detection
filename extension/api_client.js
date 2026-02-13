// API Client - Backend Communication Only

import CONFIG from './config.js';

class APIClient {
  constructor() {
    this.cache = new Map();
  }

  /**
   * Check if domain is whitelisted
   */
  isWhitelisted(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      return CONFIG.WHITELIST.some(domain => {
        return hostname === domain || hostname.endsWith('.' + domain);
      });
    } catch {
      return false;
    }
  }

  /**
   * Get cached result if available and fresh
   */
  getCached(url) {
    const cached = this.cache.get(url);
    
    if (!cached) return null;
    
    const age = Date.now() - cached.timestamp;
    
    if (age > CONFIG.CACHE_TTL_MS) {
      this.cache.delete(url);
      return null;
    }
    
    return cached.result;
  }

  /**
   * Store result in cache
   */
  setCached(url, result) {
    this.cache.set(url, {
      result: result,
      timestamp: Date.now()
    });
    
    // Limit cache size to 100 entries
    if (this.cache.size > 100) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  /**
   * Scan URL using backend ML model
   * Returns backend response directly - NO local processing
   */
async scanURL(url) {

  // 🚫 Skip search engine result pages
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();

    if (
      (hostname.includes("google.") && pathname.startsWith("/search")) ||
      (hostname.includes("bing.com") && pathname.startsWith("/search")) ||
      (hostname.includes("yahoo.com") && pathname.includes("/search"))
    ) {
      console.log("⏭ Skipping search engine result page:", url);

      return {
        url: url,
        classification: "Legitimate",
        confidence: 100,
        risk_level: "low",
        skipped: true
      };
    }
  } catch (e) {
    console.warn("Search page detection error:", e);
  }

  // ✅ Skip if whitelisted
  if (this.isWhitelisted(url)) {
    return {
      url: url,
      classification: "Legitimate",
      confidence: 100,
      risk_level: "low",
      whitelisted: true
    };
  }

  // ✅ Check cache
  const cached = this.getCached(url);
  if (cached) {
    console.log("⚡ Using cached result");
    return cached;
  }

  // ✅ Call backend
  try {
    const response = await fetch(CONFIG.API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error("Backend scan failed");
    }

    const result = await response.json();

    // Store in cache
    this.setCached(url, result);

    return result;

  } catch (error) {
    console.error("❌ Backend error:", error);

    return {
      url: url,
      classification: "Error",
      confidence: 0,
      risk_level: "unknown",
      error: true
    };
  }
}


  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }
}

// Singleton instance
const apiClient = new APIClient();

export default apiClient;