// Warning Page Logic

(function() {
  'use strict';
  
  // Load detection data from storage
  chrome.storage.local.get(['lastDetection'], (data) => {
    if (data.lastDetection) {
      displayWarning(data.lastDetection);
    } else {
      // No detection data - shouldn't happen
      document.getElementById('url').textContent = 'Unknown';
      document.getElementById('explanation').textContent = 'No detection data available';
    }
  });
  
  function displayWarning(detection) {
    // Update URL
    document.getElementById('url').textContent = detection.url || detection.originalUrl;
    
    // Update risk level
    const riskElement = document.getElementById('risk-level');
    const riskLevel = (detection.risk_level || 'high').toUpperCase();
    riskElement.textContent = riskLevel;
    
    // Color code risk level
    if (riskLevel === 'HIGH') {
      riskElement.className = 'risk-high';
    } else if (riskLevel === 'MEDIUM') {
      riskElement.className = 'risk-medium';
    }
    
    // Update confidence
    const confidencePercent = Math.round((detection.confidence || 0.9) * 100);
    document.getElementById('confidence').textContent = confidencePercent + '%';
    
    // Update explanation
    document.getElementById('explanation').textContent = 
      detection.explanation || 'Multiple phishing indicators detected';
  }
  
  // Handle "Go Back" button
  document.getElementById('go-back').addEventListener('click', () => {
    // Go back or close tab
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
    
    // If neither works, go to safe page
    setTimeout(() => {
      window.location.href = 'https://google.com';
    }, 100);
  });
  
  // Handle "Proceed Anyway" button
  document.getElementById('proceed').addEventListener('click', () => {
    chrome.storage.local.get(['lastDetection'], (data) => {
      if (data.lastDetection && data.lastDetection.originalUrl) {
        // Warn user one more time
        const confirmed = confirm(
          '⚠️ FINAL WARNING ⚠️\n\n' +
          'You are about to visit a potentially dangerous website.\n\n' +
          'Are you absolutely sure you want to continue?'
        );
        
        if (confirmed) {
          // Proceed to the original URL
          window.location.href = data.lastDetection.originalUrl;
        }
      }
    });
  });
  
  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    // Escape or Backspace = Go back
    if (e.key === 'Escape' || e.key === 'Backspace') {
      document.getElementById('go-back').click();
    }
    
    // Enter = Proceed (requires confirmation)
    if (e.key === 'Enter') {
      document.getElementById('proceed').click();
    }
  });
  
})();
