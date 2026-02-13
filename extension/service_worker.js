// Service Worker - Main Entry Point
// Architecture: Backend ML is single source of truth

import apiClient from './api_client.js';
import navigationGuard from './navigation_guard.js';
import badgeManager from './badge_manager.js';

console.log('🛡️ PhishGuard AI Service Worker Starting...');

// Initialize components
navigationGuard.init();
badgeManager.init();

/**
 * Handle messages from popup and content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender, sendResponse);
  return true; // Keep channel open for async response
});

/**
 * Message handler
 */
async function handleMessage(message, sender, sendResponse) {
  try {
    const { type } = message;

    switch (type) {
      case 'SCAN_CURRENT_TAB':
        await handleScanCurrentTab(sendResponse);
        break;

      case 'CHECK_URL':
        await handleCheckURL(message, sendResponse);
        break;

      case 'CLEAR_CACHE':
        handleClearCache(sendResponse);
        break;

      default:
        sendResponse({ error: 'Unknown message type' });
    }

  } catch (error) {
    console.error('✗ Message handler error:', error);
    sendResponse({ error: error.message });
  }
}

/**
 * Scan current tab
 */
async function handleScanCurrentTab(sendResponse) {
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      sendResponse({ error: 'No active tab found' });
      return;
    }

    const url = tab.url;

    console.log('🔍 Scanning current tab:', url);

    // Call backend API
    const result = await apiClient.scanURL(url);

    // Update badge based on backend classification
    await badgeManager.updateBadge(tab.id, result);

    // Return backend result directly
    sendResponse({
      success: true,
      url: url,
      result: result
    });

  } catch (error) {
    console.error('✗ Scan error:', error);
    sendResponse({ 
      error: error.message,
      success: false 
    });
  }
}

/**
 * Check specific URL
 */
async function handleCheckURL(message, sendResponse) {
  try {
    const { url } = message;

    if (!url) {
      sendResponse({ error: 'No URL provided' });
      return;
    }

    console.log('🔍 Checking URL:', url);

    // Call backend API
    const result = await apiClient.scanURL(url);

    // Return backend result directly
    sendResponse({
      success: true,
      url: url,
      result: result,
      // Legacy compatibility fields
      is_phishing: result.classification === 'Phishing',
      classification: result.classification,
      confidence: result.confidence,
      risk_level: result.risk_level
    });

  } catch (error) {
    console.error('✗ Check URL error:', error);
    sendResponse({ 
      error: error.message,
      success: false,
      is_phishing: false
    });
  }
}

/**
 * Clear cache
 */
function handleClearCache(sendResponse) {
  apiClient.clearCache();
  console.log('✓ Cache cleared');
  sendResponse({ success: true });
}

/**
 * Extension installed/updated
 */
chrome.runtime.onInstalled.addListener((details) => {
  console.log('✓ Extension installed/updated:', details.reason);
  
  if (details.reason === 'install') {
    console.log('🎉 PhishGuard AI installed successfully!');
  } else if (details.reason === 'update') {
    console.log('🔄 PhishGuard AI updated to version', chrome.runtime.getManifest().version);
  }
});

console.log('✓ Service Worker initialized successfully');
console.log('📡 Backend ML is single source of truth');
console.log('🚫 No local thresholds or ML logic');