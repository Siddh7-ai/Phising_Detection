// Content Script - Runs on all pages
// Intercepts link clicks and checks for phishing

(function() {
  'use strict';
  
  console.log('🛡️ Phishing Detection content script loaded');
  
  // Track if we're checking a URL
  let checkingUrl = false;
  
  /**
   * Check URL with background script
   */
  async function checkURLSafety(url) {
    return new Promise((resolve) => {
      // Check if chrome.runtime is available
      if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
        console.warn('Chrome runtime not available');
        resolve({ is_phishing: false, error: true });
        return;
      }
      
      chrome.runtime.sendMessage(
        { type: 'CHECK_URL', url: url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('Error checking URL:', chrome.runtime.lastError);
            resolve({ is_phishing: false, error: true });
          } else {
            resolve(response || { is_phishing: false, error: true });
          }
        }
      );
    });
  }
  
  /**
   * Show inline warning for suspicious link
   */
  function showInlineWarning(element, result) {
    // Safety check
    if (!document.body || !element) return;
    
    // Create warning tooltip
    const warning = document.createElement('div');
    warning.className = 'phishing-shield-warning';
    warning.style.cssText = `
      position: absolute;
      background: #ff4444;
      color: white;
      padding: 10px 15px;
      border-radius: 5px;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 6px rgba(0,0,0,0.3);
      max-width: 300px;
      font-family: Arial, sans-serif;
    `;
    
    warning.innerHTML = `
      <strong>⚠️ Warning: Suspicious Link</strong><br>
      <small>Risk: ${result.risk_level?.toUpperCase() || 'UNKNOWN'}</small><br>
      <small>${result.explanation || 'Suspicious link detected'}</small>
    `;
    
    // Position near the link
    try {
      const rect = element.getBoundingClientRect();
      warning.style.top = (window.scrollY + rect.bottom + 5) + 'px';
      warning.style.left = (window.scrollX + rect.left) + 'px';
      
      document.body.appendChild(warning);
      
      // Remove after 5 seconds
      setTimeout(() => {
        if (warning.parentNode) {
          warning.remove();
        }
      }, 5000);
    } catch (error) {
      console.error('Error positioning warning:', error);
    }
  }
  
  /**
   * Show confirmation dialog for risky link
   */
  function showConfirmDialog(url, result) {
    const confirmed = confirm(
      `⚠️ WARNING: This link appears to be suspicious!\n\n` +
      `URL: ${url}\n` +
      `Risk Level: ${result.risk_level?.toUpperCase() || 'UNKNOWN'}\n` +
      `Confidence: ${(result.confidence * 100).toFixed(0)}%\n\n` +
      `Reason: ${result.explanation || 'Suspicious link detected'}\n\n` +
      `Do you want to continue anyway?`
    );
    
    return confirmed;
  }
  
  /**
   * Find closest anchor element
   */
  function findClosestAnchor(element) {
    if (!element) return null;
    
    // If element is already an anchor
    if (element.tagName === 'A') return element;
    
    // Walk up the DOM tree
    let current = element;
    while (current && current !== document.body) {
      if (current.tagName === 'A') return current;
      current = current.parentElement;
    }
    
    return null;
  }
  
  /**
   * Handle link click
   */
  async function handleLinkClick(event) {
    const link = findClosestAnchor(event.target);
    
    if (!link || !link.href) return;
    
    // Skip internal links and anchors
    if (link.href.startsWith('#') || 
        link.href.startsWith('javascript:') ||
        link.href.startsWith('mailto:') ||
        link.href.startsWith('tel:')) {
      return;
    }
    
    // Avoid re-checking
    if (checkingUrl) return;
    
    try {
      checkingUrl = true;
      
      // Check URL
      const result = await checkURLSafety(link.href);
      
      // If phishing detected
      if (result.is_phishing && result.confidence >= 0.7) {
        event.preventDefault();
        event.stopPropagation();
        
        // Show warning
        showInlineWarning(link, result);
        
        // High-risk URLs require confirmation
        if (result.confidence >= 0.85) {
          const proceed = showConfirmDialog(link.href, result);
          
          if (proceed) {
            // User chose to proceed
            window.location.href = link.href;
          }
        }
      }
      
    } catch (error) {
      console.error('Error in link check:', error);
    } finally {
      checkingUrl = false;
    }
  }
  
  /**
   * Monitor dynamic links (for WhatsApp and other dynamic content)
   */
  function monitorDynamicLinks() {
    // Use event delegation for better performance
    document.addEventListener('click', handleLinkClick, true);
    
    // Also monitor mouseenter for preemptive checks (optional)
    document.addEventListener('mouseenter', async (event) => {
      const link = findClosestAnchor(event.target);
      if (!link || !link.href) return;
      
      // Preemptively check link on hover
      // This will cache the result for faster click handling
      checkURLSafety(link.href).catch(() => {});
    }, true);
  }
  
  /**
   * Add styles safely
   */
  function addStyles() {
    // Wait for head to be available
    if (!document.head) {
      setTimeout(addStyles, 100);
      return;
    }
    
    const style = document.createElement('style');
    style.textContent = `
      .phishing-shield-warning {
        animation: slideIn 0.3s ease-out;
      }
      
      @keyframes slideIn {
        from {
          opacity: 0;
          transform: translateY(-10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }
    `;
    document.head.appendChild(style);
  }
  
  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      monitorDynamicLinks();
      addStyles();
    });
  } else {
    monitorDynamicLinks();
    addStyles();
  }
  
})();