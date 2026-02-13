// Navigation Guard - Block Phishing Sites Based on Backend

import apiClient from './api_client.js';

class NavigationGuard {
  constructor() {
    this.pendingNavigations = new Set();
    this.blockedTabs = new Set(); // prevents re-block loop during redirect
  }

  /**
   * Initialize navigation interception
   */
  init() {
    chrome.webNavigation.onBeforeNavigate.addListener(
      (details) => this.handleNavigation(details),
      { url: [{ schemes: ['http', 'https'] }] }
    );

    console.log('✓ Navigation guard initialized');
  }

  /**
   * Handle navigation event
   */
  async handleNavigation(details) {
    // Only check main frame navigations
    if (details.frameId !== 0) return;

    const url   = details.url;
    const tabId = details.tabId;

    // Skip if this tab is currently being redirected to blocked page
    if (this.blockedTabs.has(tabId)) {
      console.log('⏭ Skipping re-check for tab being redirected:', tabId);
      return;
    }

    // Avoid duplicate checks for same tab+url
    const navigationKey = `${tabId}-${url}`;
    if (this.pendingNavigations.has(navigationKey)) {
      return;
    }

    this.pendingNavigations.add(navigationKey);

    try {
      console.log('🔍 Checking navigation:', url);

      // Scan URL using backend ML
      const result = await apiClient.scanURL(url);

      // Trust backend classification 100%
      if (result.classification === 'Phishing') {
        console.log('🚫 BLOCKING - Backend classified as Phishing:', url);
        await this.blockNavigation(tabId, url, result);
      } else {
        console.log('✓ ALLOWING - Backend classification:', result.classification);
      }

    } catch (error) {
      console.error('✗ Navigation check error:', error);
      // On error, fail open (allow navigation)
    } finally {
      setTimeout(() => {
        this.pendingNavigations.delete(navigationKey);
      }, 2000);
    }
  }

  /**
   * Block navigation and redirect to blocked page
   */
  async blockNavigation(tabId, url, result) {
    try {
      // Mark tab as redirecting so we skip the next navigation event it fires
      this.blockedTabs.add(tabId);

      // Store detection data for blocked_page.js to read
      await chrome.storage.local.set({
        lastDetection: {
          url:            url,
          originalUrl:    url,
          classification: result.classification,
          confidence:     result.confidence  ?? 95,
          risk_level:     result.risk_level  ?? 'high',
          modules:        result.modules     || {},
          timestamp:      Date.now()
        }
      });

      // Redirect to blocked page
      const blockedPageUrl = chrome.runtime.getURL('blocked.html');
      await chrome.tabs.update(tabId, { url: blockedPageUrl });

      console.log('→ Redirected to blocked page for:', url);

    } catch (error) {
      console.error('✗ Error blocking navigation:', error);
      this.blockedTabs.delete(tabId);
    } finally {
      // Release the redirect lock after 3 seconds
      setTimeout(() => {
        this.blockedTabs.delete(tabId);
      }, 3000);
    }
  }
}

// Singleton instance
const navigationGuard = new NavigationGuard();

export default navigationGuard;