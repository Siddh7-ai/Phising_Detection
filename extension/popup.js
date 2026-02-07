// Popup Script - Complete Rewrite for Auto-Scan with Charts & Screenshot

(function() {
  'use strict';
  
  const API_URL = 'http://localhost:5000/api/scan';
  
  let currentTabUrl = null;
  let currentTabId = null;
  
  // Initialize
  document.addEventListener('DOMContentLoaded', init);
  
  function init() {
    // Get current tab info
    getCurrentTab();
    
    // Attach event listeners
    document.getElementById('scan-btn').addEventListener('click', startScan);
    document.getElementById('rescan-btn').addEventListener('click', startScan);
  }
  
  /**
   * Get current active tab URL
   */
  async function getCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (tab) {
        currentTabUrl = tab.url;
        currentTabId = tab.id;
        
        console.log('Current tab URL:', currentTabUrl);
        
        // Validate URL
        if (currentTabUrl.startsWith('chrome://') || 
            currentTabUrl.startsWith('chrome-extension://') ||
            currentTabUrl.startsWith('about:')) {
          disableScan('Cannot scan internal pages');
        } else {
          enableScan();
        }
      } else {
        disableScan('No active tab found');
      }
    } catch (error) {
      console.error('Error getting tab:', error);
      disableScan('Error accessing tab');
    }
  }
  
  function enableScan() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.textContent = '🔍 Scan Current Page';
  }
  
  function disableScan(reason) {
    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.textContent = reason || 'Cannot scan this page';
  }
  
  /**
   * Start the scan process
   */
  async function startScan() {
    if (!currentTabUrl) {
      showError('No URL to scan');
      return;
    }
    
    console.log('Starting scan for:', currentTabUrl);
    
    // Show loading state
    showLoading(currentTabUrl);
    
    try {
      // Step 1: Capture screenshot (parallel with API call)
      const screenshotPromise = captureScreenshot();
      
      // Step 2: Call ML API
      const resultPromise = checkURLWithAPI(currentTabUrl);
      
      // Wait for both
      const [screenshot, result] = await Promise.all([screenshotPromise, resultPromise]);
      
      console.log('Scan complete:', result);
      
      // Step 3: Display result
      displayResult(result, screenshot);
      
    } catch (error) {
      console.error('Scan error:', error);
      showError(error.message || 'Scan failed. Check if backend is running.');
    }
  }
  
  /**
   * Capture screenshot of current tab
   */
  async function captureScreenshot() {
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(null, {
        format: 'png',
        quality: 80
      });
      return dataUrl;
    } catch (error) {
      console.error('Screenshot error:', error);
      return null;
    }
  }
  
  /**
   * Call ML API to check URL
   */
  async function checkURLWithAPI(url) {
    console.log('Calling API:', API_URL);
    console.log('Sending URL:', url);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout
    
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ url: url }),
        signal: controller.signal,
        mode: 'cors'
      });
      
      clearTimeout(timeoutId);
      
      console.log('API Response status:', response.status);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error response:', errorText);
        throw new Error(`API Error: ${response.status} - ${errorText}`);
      }
      
      const data = await response.json();
      console.log('API Response data:', data);
      
      // Transform API response to internal format
      return {
        url: data.url,
        classification: data.classification, // "Phishing" or "Legitimate"
        confidence: data.confidence, // 0-100
        model: data.model,
        metrics: data.metrics,
        timestamp: data.timestamp
      };
      
    } catch (error) {
      console.error('API Call error:', error);
      
      if (error.name === 'AbortError') {
        throw new Error('Request timeout - Backend not responding');
      }
      
      if (error.message.includes('Failed to fetch')) {
        throw new Error('Cannot connect to backend. Is it running on http://localhost:5000?');
      }
      
      throw error;
    }
  }
  
  /**
   * Show loading animation
   */
  function showLoading(url) {
    document.querySelector('.scan-section').style.display = 'none';
    document.getElementById('result-container').classList.remove('active');
    
    const loadingContainer = document.getElementById('loading-container');
    loadingContainer.classList.add('active');
    
    // Show URL being scanned
    document.getElementById('loading-url').textContent = url;
  }
  
  /**
   * Display scan result with animations
   */
  function displayResult(result, screenshot) {
    // Hide loading
    document.getElementById('loading-container').classList.remove('active');
    
    // Show result container
    const resultContainer = document.getElementById('result-container');
    resultContainer.classList.add('active');
    
    // Display screenshot
    if (screenshot) {
      document.getElementById('screenshot-img').src = screenshot;
      document.getElementById('screenshot-img').style.display = 'block';
      document.getElementById('screenshot-placeholder').style.display = 'none';
    } else {
      document.getElementById('screenshot-img').style.display = 'none';
      document.getElementById('screenshot-placeholder').style.display = 'flex';
    }
    
    // Determine if phishing
    const isPhishing = result.classification === 'Phishing' || result.classification === 'Suspicious';
    
    // Update header
    const resultIcon = document.getElementById('result-icon');
    const resultTitle = document.getElementById('result-title');
    const resultSubtitle = document.getElementById('result-subtitle');
    
    if (isPhishing) {
      resultIcon.textContent = '⚠️';
      resultTitle.textContent = result.classification === 'Suspicious' ? 'Suspicious Website' : 'Phishing Detected';
      resultTitle.className = 'result-title danger';
      resultSubtitle.textContent = 'This website appears to be malicious';
    } else {
      resultIcon.textContent = '✅';
      resultTitle.textContent = 'Website Appears Safe';
      resultTitle.className = 'result-title safe';
      resultSubtitle.textContent = 'No immediate threats detected';
    }
    
    // Animate confidence meter
    animateConfidenceMeter(result.confidence, isPhishing);
    
    // Populate metrics
    populateMetrics(result.metrics, isPhishing);
  }
  
  /**
   * Animate circular confidence meter
   */
  function animateConfidenceMeter(confidence, isPhishing) {
    const circle = document.getElementById('confidence-circle');
    const valueEl = document.getElementById('confidence-value');
    
    // Circle properties
    const radius = 65;
    const circumference = 2 * Math.PI * radius;
    
    // Set color based on result
    const color = isPhishing ? '#dc3545' : '#28a745';
    circle.style.stroke = color;
    valueEl.style.color = color;
    
    // Reset
    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = circumference;
    
    // Animate
    setTimeout(() => {
      const offset = circumference - (confidence / 100) * circumference;
      circle.style.strokeDashoffset = offset;
      
      // Animate counter
      animateCounter(valueEl, 0, confidence, 1000);
    }, 100);
  }
  
  /**
   * Animate number counter
   */
  function animateCounter(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16); // 60fps
    let current = start;
    
    const timer = setInterval(() => {
      current += increment;
      if (current >= end) {
        current = end;
        clearInterval(timer);
      }
      element.textContent = Math.round(current) + '%';
    }, 16);
  }
  
  /**
   * Populate metrics box
   */
  function populateMetrics(metrics, isPhishing) {
    const metricsBox = document.getElementById('metrics-box');
    metricsBox.innerHTML = '';
    
    // Create metric items
    const items = [
      {
        label: 'Classification',
        value: isPhishing ? 'Phishing' : 'Legitimate',
        status: isPhishing ? 'bad' : 'good'
      },
      {
        label: 'Domain Age',
        value: metrics.domain_age || 'Unknown',
        status: getAgeStatus(metrics.domain_age)
      },
      {
        label: 'HTTPS',
        value: metrics.https ? 'Yes ✓' : 'No ✗',
        status: metrics.https ? 'good' : 'bad'
      },
      {
        label: 'URL Length',
        value: metrics.url_length || 'N/A',
        status: metrics.url_length > 75 ? 'warning' : 'good'
      },
      {
        label: 'Suspicious Keywords',
        value: metrics.suspicious_keywords ? 'Detected' : 'None',
        status: metrics.suspicious_keywords ? 'bad' : 'good'
      },
      {
        label: 'IP Address Used',
        value: metrics.has_ip ? 'Yes' : 'No',
        status: metrics.has_ip ? 'bad' : 'good'
      }
    ];
    
    items.forEach(item => {
      const metricItem = document.createElement('div');
      metricItem.className = 'metric-item';
      
      metricItem.innerHTML = `
        <span class="metric-label">${item.label}</span>
        <span class="metric-value ${item.status}">${item.value}</span>
      `;
      
      metricsBox.appendChild(metricItem);
    });
  }
  
  /**
   * Determine status based on domain age
   */
  function getAgeStatus(age) {
    if (!age || age === 'Unknown') return 'warning';
    
    const numDays = parseInt(age);
    if (isNaN(numDays)) return 'warning';
    
    if (numDays < 30) return 'bad';
    if (numDays < 180) return 'warning';
    return 'good';
  }
  
  /**
   * Show error message
   */
  function showError(message) {
    document.getElementById('loading-container').classList.remove('active');
    
    const resultContainer = document.getElementById('result-container');
    resultContainer.classList.add('active');
    
    document.getElementById('screenshot-img').style.display = 'none';
    document.getElementById('screenshot-placeholder').style.display = 'flex';
    document.querySelector('.screenshot-placeholder-icon').textContent = '⚠️';
    document.querySelector('.screenshot-placeholder div:last-child').textContent = 'Error occurred';
    
    document.getElementById('result-icon').textContent = '❌';
    document.getElementById('result-title').textContent = 'Scan Failed';
    document.getElementById('result-title').className = 'result-title danger';
    document.getElementById('result-subtitle').textContent = message;
    
    document.getElementById('metrics-box').innerHTML = `
      <div class="metric-item">
        <span class="metric-label">Error</span>
        <span class="metric-value bad">${message}</span>
      </div>
    `;
    
    const circle = document.getElementById('confidence-circle');
    circle.style.strokeDashoffset = 2 * Math.PI * 65;
    document.getElementById('confidence-value').textContent = '0%';
  }
  
})();