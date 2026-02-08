// WhatsApp-specific Content Script
// Specialized protection for WhatsApp Web links

(function() {
  'use strict';
  
  console.log('🛡️ WhatsApp Phishing Protection active');
  
  let checkingLink = false;
  
  /**
   * Extract URL from WhatsApp link element
   */
  function extractWhatsAppURL(element) {
    // WhatsApp wraps links in specific elements
    const linkEl = element.querySelector('a') || element;
    
    if (linkEl.href && linkEl.href !== 'javascript:void(0)') {
      return linkEl.href;
    }
    
    // Try to extract from onclick or data attributes
    const onclick = linkEl.getAttribute('onclick');
    if (onclick) {
      const match = onclick.match(/https?:\/\/[^\s'"]+/);
      if (match) return match[0];
    }
    
    // Get text content as fallback
    const text = element.textContent.trim();
    if (text.match(/^https?:\/\//)) {
      return text;
    }
    
    return null;
  }
  
  /**
   * Check if element is a WhatsApp message link
   */
  function isWhatsAppLink(element) {
    // Check for WhatsApp link classes
    return element.classList.contains('_11JPr') || // WhatsApp link class
           element.querySelector('a[href^="http"]') ||
           (element.tagName === 'A' && element.href.startsWith('http'));
  }
  
  /**
   * Show WhatsApp-style warning
   */
  function showWhatsAppWarning(url, result) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    `;
    
    // Create warning dialog
    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: white;
      border-radius: 12px;
      padding: 30px;
      max-width: 500px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
      border-top: 4px solid ${riskColor};
    `;
    
    // Green theme colors
    const riskColor = result.risk_level === 'high' ? '#ef4444' : '#f59e0b';
    const greenPrimary = '#22c55e';
    const greenDark = '#16a34a';
    
    dialog.innerHTML = `
      <div style="text-align: center; margin-bottom: 20px;">
        <div style="font-size: 60px; margin-bottom: 10px;">⚠️</div>
        <h2 style="color: ${riskColor}; margin: 0 0 10px 0;">Warning: Suspicious Link</h2>
        <p style="color: #666; font-size: 14px;">This link may be attempting to steal your data</p>
      </div>
      
      <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
        <div style="margin-bottom: 10px;">
          <strong>URL:</strong><br>
          <small style="word-break: break-all; color: #666;">${url}</small>
        </div>
        <div style="margin-bottom: 10px;">
          <strong>Risk Level:</strong> 
          <span style="color: ${riskColor}; font-weight: bold;">${result.risk_level.toUpperCase()}</span>
        </div>
        <div style="margin-bottom: 10px;">
          <strong>Confidence:</strong> ${(result.confidence * 100).toFixed(0)}%
        </div>
        <div>
          <strong>Reason:</strong><br>
          <small>${result.explanation}</small>
        </div>
      </div>
      
      <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 3px;">
        <strong>⚠️ Security Warning:</strong><br>
        <small>
          Phishing sites often impersonate legitimate services to steal passwords, 
          credit card info, and personal data. Only proceed if you're absolutely sure this link is safe.
        </small>
      </div>
      
      <div style="display: flex; gap: 10px;">
        <button id="phishing-go-back" style="
          flex: 1;
          padding: 12px 20px;
          background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: bold;
          cursor: pointer;
          box-shadow: 0 4px 14px rgba(34, 197, 94, 0.3);
          transition: all 0.3s ease;
        " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 20px rgba(34, 197, 94, 0.4)';" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 14px rgba(34, 197, 94, 0.3)';">
          ✓ Go Back (Safe)
        </button>
        <button id="phishing-continue" style="
          flex: 1;
          padding: 12px 20px;
          background: #6b7280;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          cursor: pointer;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
          transition: all 0.3s ease;
        " onmouseover="this.style.background='#4b5563'; this.style.transform='translateY(-1px)';" onmouseout="this.style.background='#6b7280'; this.style.transform='translateY(0)';">
          Continue Anyway
        </button>
      </div>
      
      <div style="margin-top: 15px; text-align: center; font-size: 12px; color: #999;">
        Protected by Phishing Detection Shield
      </div>
    `;
    
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Handle buttons
    return new Promise((resolve) => {
      document.getElementById('phishing-go-back').onclick = () => {
        overlay.remove();
        resolve(false);
      };
      
      document.getElementById('phishing-continue').onclick = () => {
        overlay.remove();
        resolve(true);
      };
      
      // Close on overlay click
      overlay.onclick = (e) => {
        if (e.target === overlay) {
          overlay.remove();
          resolve(false);
        }
      };
    });
  }
  
  /**
   * Check URL with background script
   */
  async function checkURL(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'CHECK_URL', url: url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('Error:', chrome.runtime.lastError);
            resolve({ is_phishing: false, error: true });
          } else {
            resolve(response);
          }
        }
      );
    });
  }
  
  /**
   * Handle WhatsApp link click
   */
  async function handleWhatsAppLinkClick(event) {
    const element = event.target.closest('[role="button"], a, ._11JPr');
    
    if (!element || !isWhatsAppLink(element)) return;
    
    const url = extractWhatsAppURL(element);
    
    if (!url) return;
    
    // Skip if already checking
    if (checkingLink) return;
    
    try {
      checkingLink = true;
      
      console.log('Checking WhatsApp link:', url);
      
      // Check URL
      const result = await checkURL(url);
      
      // If phishing detected
      if (result.is_phishing && result.confidence >= 0.7) {
        event.preventDefault();
        event.stopPropagation();
        
        // Show warning and wait for user decision
        const proceed = await showWhatsAppWarning(url, result);
        
        if (proceed) {
          // User chose to proceed - open in new tab with warning
          window.open(url, '_blank', 'noopener,noreferrer');
        }
      }
      
    } catch (error) {
      console.error('Error checking WhatsApp link:', error);
    } finally {
      checkingLink = false;
    }
  }
  
  /**
   * Initialize WhatsApp protection
   */
  function initializeWhatsAppProtection() {
    // Intercept clicks on WhatsApp Web
    document.addEventListener('click', handleWhatsAppLinkClick, true);
    
    console.log('✓ WhatsApp link protection enabled');
  }
  
  // Wait for WhatsApp to load, then initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeWhatsAppProtection);
  } else {
    initializeWhatsAppProtection();
  }
  
  // Re-initialize if WhatsApp reloads content
  const observer = new MutationObserver((mutations) => {
    // Check if main WhatsApp container is present
    if (document.querySelector('#app')) {
      console.log('WhatsApp content detected');
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
})();