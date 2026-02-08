// Popup Script - Complete Integration with Green Theme
// PhishGuard AI Extension - Auto-Scan with Charts & Screenshot

(function() {
  'use strict';
  
  const API_URL = 'http://localhost:5000/api/scan';
  
  let currentTabUrl = null;
  let currentTabId = null;
  
  // Initialize
  document.addEventListener('DOMContentLoaded', init);
  
  function init() {
    // Set default theme state
    document.body.classList.add('safe');
    
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
   * Display scan result with animations and theme updates
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
    
    // Determine classification and threat level
    const classification = result.classification.toLowerCase();
    let state = 'safe';
    let stateClass = 'safe';
    let isPhishing = false;
    
    if (classification === 'phishing' || classification === 'malicious') {
      state = 'phishing';
      stateClass = 'danger';
      isPhishing = true;
    } else if (classification === 'suspicious' || classification === 'warning') {
      state = 'warning';
      stateClass = 'warning';
      isPhishing = true; // Treat suspicious as potentially harmful
    } else {
      state = 'safe';
      stateClass = 'safe';
      isPhishing = false;
    }
    
    // Update body theme class
    updateBodyTheme(state);
    
    // Update result header
    updateResultHeader(state, stateClass, classification);
    
    // Animate confidence meter
    animateConfidenceMeter(result.confidence, stateClass);
    
    // Populate metrics
    populateMetrics(result.metrics, stateClass, classification);
  }
  
  /**
   * Update body theme class for dynamic color switching
   */
  function updateBodyTheme(state) {
    // Remove all state classes
    document.body.classList.remove('safe', 'phishing', 'warning');
    
    // Add new state class
    document.body.classList.add(state);
  }
  
  /**
   * Update result header with appropriate icons and text
   */
  function updateResultHeader(state, stateClass, classification) {
    const resultIcon = document.getElementById('result-icon');
    const resultTitle = document.getElementById('result-title');
    const resultSubtitle = document.getElementById('result-subtitle');
    
    if (state === 'safe') {
      resultIcon.textContent = '✅';
      resultTitle.textContent = 'Website Appears Safe';
      resultTitle.className = 'result-title safe';
      resultSubtitle.textContent = 'No immediate threats detected';
    } else if (state === 'phishing') {
      resultIcon.textContent = '🚨';
      resultTitle.textContent = 'Phishing Detected!';
      resultTitle.className = 'result-title danger';
      resultSubtitle.textContent = 'This website appears to be malicious';
    } else if (state === 'warning') {
      resultIcon.textContent = '⚠️';
      resultTitle.textContent = 'Suspicious Elements Found';
      resultTitle.className = 'result-title warning';
      resultSubtitle.textContent = 'Proceed with caution';
    }
  }
  
  /**
   * Animate circular confidence meter with theme colors
   */
  function animateConfidenceMeter(confidence, stateClass) {
    const circle = document.getElementById('confidence-circle');
    const valueEl = document.getElementById('confidence-value');
    
    // Circle properties
    const radius = 65;
    const circumference = 2 * Math.PI * radius;
    
    // Apply state class to circle (use setAttribute for SVG)
    circle.setAttribute('class', `confidence-progress ${stateClass}`);
    
    // Apply state class to value (regular HTML element)
    valueEl.className = `confidence-value ${stateClass}`;
    
    // Reset circle
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = circumference;
    
    // Animate after short delay
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
   * Populate metrics box with theme-aware status colors
   */
  function populateMetrics(metrics, stateClass, classification) {
    const metricsBox = document.getElementById('metrics-box');
    metricsBox.innerHTML = '';
    
    // Create metric items with proper status
    const items = [
      {
        label: 'Classification',
        value: classification.charAt(0).toUpperCase() + classification.slice(1),
        status: stateClass === 'safe' ? 'good' : (stateClass === 'warning' ? 'warning' : 'bad')
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
        status: getUrlLengthStatus(metrics.url_length)
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
      
      const metricLabel = document.createElement('span');
      metricLabel.className = 'metric-label';
      metricLabel.textContent = item.label;
      
      const metricValue = document.createElement('span');
      metricValue.className = `metric-value ${item.status}`;
      metricValue.textContent = item.value;
      
      metricItem.appendChild(metricLabel);
      metricItem.appendChild(metricValue);
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
   * Determine status based on URL length
   */
  function getUrlLengthStatus(length) {
    if (!length || length === 'N/A') return 'warning';
    
    const numLength = parseInt(length);
    if (isNaN(numLength)) return 'warning';
    
    if (numLength > 100) return 'bad';
    if (numLength > 75) return 'warning';
    return 'good';
  }
  
  /**
   * Show error message with red theme
   */
  function showError(message) {
    // Update body theme to phishing/error state
    updateBodyTheme('phishing');
    
    // Hide loading
    document.getElementById('loading-container').classList.remove('active');
    
    // Show result container
    const resultContainer = document.getElementById('result-container');
    resultContainer.classList.add('active');
    
    // Update screenshot placeholder
    document.getElementById('screenshot-img').style.display = 'none';
    const placeholder = document.getElementById('screenshot-placeholder');
    placeholder.style.display = 'flex';
    document.querySelector('.screenshot-placeholder-icon').textContent = '⚠️';
    document.querySelector('.screenshot-placeholder div:last-child').textContent = 'Error occurred';
    
    // Update result header
    const resultIcon = document.getElementById('result-icon');
    const resultTitle = document.getElementById('result-title');
    const resultSubtitle = document.getElementById('result-subtitle');
    
    resultIcon.textContent = '❌';
    resultTitle.textContent = 'Scan Failed';
    resultTitle.className = 'result-title danger';
    resultSubtitle.textContent = message;
    
    // Update confidence meter
    const circle = document.getElementById('confidence-circle');
    const valueEl = document.getElementById('confidence-value');
    
    // Use setAttribute for SVG element
    circle.setAttribute('class', 'confidence-progress danger');
    valueEl.className = 'confidence-value danger';
    
    const radius = 65;
    const circumference = 2 * Math.PI * radius;
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = circumference;
    valueEl.textContent = '0%';
    
    // Update metrics
    const metricsBox = document.getElementById('metrics-box');
    metricsBox.innerHTML = '';
    
    const metricItem = document.createElement('div');
    metricItem.className = 'metric-item';
    
    const metricLabel = document.createElement('span');
    metricLabel.className = 'metric-label';
    metricLabel.textContent = 'Error';
    
    const metricValue = document.createElement('span');
    metricValue.className = 'metric-value bad';
    metricValue.textContent = message;
    
    metricItem.appendChild(metricLabel);
    metricItem.appendChild(metricValue);
    metricsBox.appendChild(metricItem);
  }
  
})();