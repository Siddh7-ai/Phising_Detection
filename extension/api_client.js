// API Client - Backend ML Only
// No whitelist, no local logic — 100% ML model decisions

import CONFIG from './config.js';

class APIClient {
  constructor() {
    this.cache = new Map();
  }

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

  setCached(url, result) {
    this.cache.set(url, { result, timestamp: Date.now() });
    if (this.cache.size > 100) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  async scanURL(url) {
    // 🚫 Skip internal browser pages only
    try {
      const urlObj = new URL(url);
      const scheme = urlObj.protocol;
      if (scheme === 'chrome:' || scheme === 'chrome-extension:' || 
          scheme === 'about:' || scheme === 'file:') {
        console.log('⏭ Skipping internal page:', url);
        return {
          url, classification: 'Legitimate',
          confidence: 0, risk_level: 'low', skipped: true
        };
      }
    } catch (e) {
      console.warn('URL parse error:', e);
    }

    // ✅ Check cache
    const cached = this.getCached(url);
    if (cached) {
      console.log('⚡ Using cached result for:', url);
      return cached;
    }

    // ✅ Call backend ML model
    try {
      console.log('🔍 Sending to ML model:', url);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT_MS);

      const response = await fetch(CONFIG.API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) throw new Error(`Backend error: ${response.status}`);

      const result = await response.json();
      this.setCached(url, result);
      return result;

    } catch (error) {
      if (error.name === 'AbortError') {
        console.error('❌ Request timed out:', url);
      } else {
        console.error('❌ Backend error:', error);
      }
      return {
        url, classification: 'Error',
        confidence: 0, risk_level: 'unknown', error: true
      };
    }
  }

  clearCache() {
    this.cache.clear();
  }
}

const apiClient = new APIClient();
export default apiClient;