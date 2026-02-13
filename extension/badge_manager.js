// Badge Manager - Visual Indicator Based on Backend Classification

class BadgeManager {
  /**
   * Update badge based on backend classification
   * NO thresholds, NO confidence checks - trust backend 100%
   */
  async updateBadge(tabId, result) {
    try {
      const classification = result.classification;

      // Map backend classification to badge
      let badgeText = '';
      let badgeColor = '';
      let title = '';

      if (classification === 'Phishing') {
        badgeText = '!';
        badgeColor = '#ef4444'; // Red
        title = 'Phishing Detected - Site Blocked';
      } else if (classification === 'Suspicious') {
        badgeText = '?';
        badgeColor = '#f59e0b'; // Orange
        title = 'Suspicious Site - Exercise Caution';
      } else if (classification === 'Legitimate') {
        badgeText = '✓';
        badgeColor = '#22c55e'; // Green
        title = 'Site Appears Safe';
      } else {
        // Unknown classification
        badgeText = '';
        badgeColor = '#6b7280'; // Gray
        title = 'PhishGuard AI';
      }

      // Update badge
      await chrome.action.setBadgeText({ 
        tabId: tabId, 
        text: badgeText 
      });

      await chrome.action.setBadgeBackgroundColor({ 
        tabId: tabId, 
        color: badgeColor 
      });

      await chrome.action.setTitle({ 
        tabId: tabId, 
        title: title 
      });

      console.log(`✓ Badge updated: ${badgeText} (${classification})`);

    } catch (error) {
      console.error('✗ Error updating badge:', error);
    }
  }

  /**
   * Clear badge
   */
  async clearBadge(tabId) {
    try {
      await chrome.action.setBadgeText({ tabId: tabId, text: '' });
      await chrome.action.setTitle({ tabId: tabId, title: 'PhishGuard AI' });
    } catch (error) {
      console.error('✗ Error clearing badge:', error);
    }
  }

  /**
   * Listen for tab updates and update badge
   */
  init() {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        // Badge will be updated by navigation guard
      }
    });

    console.log('✓ Badge manager initialized');
  }
}

// Singleton instance
const badgeManager = new BadgeManager();

export default badgeManager;