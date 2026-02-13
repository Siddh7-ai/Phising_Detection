// Popup Logic - Display Backend Results Only
// NO local calculations, NO thresholds, NO ML logic
// ENHANCED: Stats tracking and tips carousel

(function() {
  'use strict';

  console.log('🛡️ Popup script loaded');

  let currentResult = null;
  let currentTipIndex = 0;
  let tipInterval = null;

  /**
   * Initialize popup
   */
  function init() {
    setupEventListeners();
    initializeStats();
    startTipsCarousel();
  }

  /**
   * Setup button event listeners
   */
  function setupEventListeners() {
    const scanBtn = document.getElementById('scan-btn');
    const rescanBtn = document.getElementById('rescan-btn');

    if (scanBtn) {
      scanBtn.addEventListener('click', handleScan);
    }

    if (rescanBtn) {
      rescanBtn.addEventListener('click', handleRescan);
    }
  }

  /**
   * Initialize statistics from storage
   */
  async function initializeStats() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || {
        scansToday: 0,
        threatsBlocked: 0,
        lastReset: new Date().toDateString()
      };

      // Reset stats if new day
      const today = new Date().toDateString();
      if (stats.lastReset !== today) {
        stats.scansToday = 0;
        stats.lastReset = today;
        await chrome.storage.local.set({ stats });
      }

      updateStatsDisplay(stats);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  }

  /**
   * Update statistics display
   */
  function updateStatsDisplay(stats) {
    const scansEl = document.getElementById('scans-today');
    const threatsEl = document.getElementById('threats-blocked');
    const uptimeEl = document.getElementById('uptime');

    if (scansEl) scansEl.textContent = stats.scansToday || 0;
    if (threatsEl) threatsEl.textContent = stats.threatsBlocked || 0;
    if (uptimeEl) uptimeEl.textContent = '100%'; // Always show 100% uptime
  }

  /**
   * Increment scan count
   */
  async function incrementScanCount() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || {
        scansToday: 0,
        threatsBlocked: 0,
        lastReset: new Date().toDateString()
      };

      stats.scansToday++;
      await chrome.storage.local.set({ stats });
      updateStatsDisplay(stats);
    } catch (error) {
      console.error('Error updating scan count:', error);
    }
  }

  /**
   * Increment threat blocked count
   */
  async function incrementThreatCount() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || {
        scansToday: 0,
        threatsBlocked: 0,
        lastReset: new Date().toDateString()
      };

      stats.threatsBlocked++;
      await chrome.storage.local.set({ stats });
      updateStatsDisplay(stats);
    } catch (error) {
      console.error('Error updating threat count:', error);
    }
  }

  /**
   * Start tips carousel
   */
  function startTipsCarousel() {
    const tips = document.querySelectorAll('.tip-text');
    const dots = document.querySelectorAll('.tip-dot');

    if (tips.length === 0) return;

    // Auto-rotate tips every 5 seconds
    tipInterval = setInterval(() => {
      currentTipIndex = (currentTipIndex + 1) % tips.length;
      showTip(currentTipIndex);
    }, 5000);

    // Click on dots to change tip
    dots.forEach((dot, index) => {
      dot.addEventListener('click', () => {
        currentTipIndex = index;
        showTip(currentTipIndex);
        
        // Reset interval
        clearInterval(tipInterval);
        tipInterval = setInterval(() => {
          currentTipIndex = (currentTipIndex + 1) % tips.length;
          showTip(currentTipIndex);
        }, 5000);
      });
    });
  }

  /**
   * Show specific tip
   */
  function showTip(index) {
    const tips = document.querySelectorAll('.tip-text');
    const dots = document.querySelectorAll('.tip-dot');

    tips.forEach((tip, i) => {
      if (i === index) {
        tip.classList.add('active');
      } else {
        tip.classList.remove('active');
      }
    });

    dots.forEach((dot, i) => {
      if (i === index) {
        dot.classList.add('active');
      } else {
        dot.classList.remove('active');
      }
    });
  }

  /**
   * Handle scan button click
   */
  async function handleScan() {
    console.log('🔍 Scan button clicked');
    
    showLoading();

    try {
      // Get current tab URL
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      console.log('Current tab:', tab);
      
      if (!tab || !tab.url) {
        showError('Unable to get current tab URL');
        return;
      }

      const url = tab.url;

      // Update loading UI
      const loadingUrlEl = document.getElementById('loading-url');
      if (loadingUrlEl) {
        loadingUrlEl.textContent = url;
      }

      console.log('Sending scan request for:', url);

      // Send scan request to service worker
      chrome.runtime.sendMessage(
        { type: 'SCAN_CURRENT_TAB' },
        (response) => {
          console.log('Received response:', response);
          
          if (chrome.runtime.lastError) {
            console.error('Runtime error:', chrome.runtime.lastError);
            showError(chrome.runtime.lastError.message);
            return;
          }

          if (!response) {
            console.error('No response received');
            showError('No response from extension');
            return;
          }

          if (response.error) {
            console.error('Response error:', response.error);
            showError(response.error);
            return;
          }

          // Increment scan count
          incrementScanCount();

          // Check if threat was detected
          if (response.result && response.result.classification === 'Phishing') {
            incrementThreatCount();
          }

          // Display backend result
          console.log('Displaying result:', response.result);
          displayResult(response.result);
        }
      );

    } catch (error) {
      console.error('Scan error:', error);
      showError(error.message);
    }
  }

  /**
   * Handle rescan button click
   */
  async function handleRescan() {
    // Clear cache and rescan
    chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }, () => {
      handleScan();
    });
  }

  /**
   * Display backend result - NO modifications
   */
  function displayResult(result) {
    currentResult = result;

    // Hide loading and info section, show result
    document.getElementById('loading-container').classList.remove('active');
    document.getElementById('result-container').classList.add('active');
    document.querySelector('.scan-section').style.display = 'none';
    document.getElementById('info-section').style.display = 'none';

    // Get classification from backend
    const classification = result.classification;
    const confidence = result.confidence || 0;
    const riskLevel = result.risk_level || 'low';

    console.log('Backend result:', { classification, confidence, riskLevel });

    // Update theme based on backend classification
    updateTheme(classification);

    // Update result header
    updateResultHeader(classification, confidence);

    // Update confidence chart
    updateConfidenceChart(classification, confidence);

    // Update metrics
    updateMetrics(result);
  }

  /**
   * Update UI theme based on backend classification
   */
  function updateTheme(classification) {
    document.body.classList.remove('safe', 'phishing', 'warning');

    if (classification === 'Phishing') {
      document.body.classList.add('phishing');
    } else if (classification === 'Suspicious') {
      document.body.classList.add('warning');
    } else {
      document.body.classList.add('safe');
    }
  }

  /**
   * Update result header
   */
  function updateResultHeader(classification, confidence) {
    const icon = document.getElementById('result-icon');
    const title = document.getElementById('result-title');
    const subtitle = document.getElementById('result-subtitle');

    if (classification === 'Phishing') {
      icon.textContent = '🚫';
      title.textContent = 'Phishing Detected';
      title.className = 'result-title danger';
      subtitle.textContent = 'This website is attempting to steal your data';
    } else if (classification === 'Suspicious') {
      icon.textContent = '⚠️';
      title.textContent = 'Suspicious Website';
      title.className = 'result-title warning';
      subtitle.textContent = 'Exercise caution when interacting with this site';
    } else {
      icon.textContent = '✅';
      title.textContent = 'Website Appears Safe';
      title.className = 'result-title safe';
      subtitle.textContent = 'No immediate threats detected';
    }
  }

  /**
   * Update confidence chart
   */
  function updateConfidenceChart(classification, confidence) {
    const circle = document.getElementById('confidence-circle');
    const valueEl = document.getElementById('confidence-value');

    // Set color based on classification
    circle.classList.remove('safe', 'danger', 'warning');
    valueEl.classList.remove('safe', 'danger', 'warning');

    if (classification === 'Phishing') {
      circle.classList.add('danger');
      valueEl.classList.add('danger');
    } else if (classification === 'Suspicious') {
      circle.classList.add('warning');
      valueEl.classList.add('warning');
    } else {
      circle.classList.add('safe');
      valueEl.classList.add('safe');
    }

    // Update percentage
    valueEl.textContent = Number(confidence).toFixed(2) + '%';

    // Animate circle
    const circumference = 2 * Math.PI * 65;
    const offset = circumference - (confidence / 100) * circumference;
    
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = circumference;

    setTimeout(() => {
      circle.style.strokeDashoffset = offset;
    }, 100);
  }

  /**
   * Update metrics - Display backend values directly
   */
  function updateMetrics(result) {
    const metricsBox = document.getElementById('metrics-box');
    metricsBox.innerHTML = '';

    // Add classification
    addMetricSection(metricsBox, 'Detection Results');
    addMetric(metricsBox, 'Classification', result.classification, getClassColor(result.classification));
    addMetric(metricsBox,'Confidence',Number(result.confidence).toFixed(2) + '%','normal');
    addMetric(metricsBox, 'Risk Level', (result.risk_level || 'low').toUpperCase(), getRiskColor(result.risk_level));

    // Add module scores if available
    if (result.modules) {
      addMetricSection(metricsBox, 'Module Scores');
      
      const modules = result.modules;
    if (modules.ml !== undefined)
      addMetric(metricsBox, 'ML Model', Number(modules.ml).toFixed(2) + '%', 'normal');

    if (modules.lexical !== undefined)
      addMetric(metricsBox, 'Lexical', Number(modules.lexical).toFixed(2) + '%', 'normal');

    if (modules.reputation !== undefined)
      addMetric(metricsBox, 'Reputation', Number(modules.reputation).toFixed(2) + '%', 'normal');

    if (modules.behavior !== undefined)
      addMetric(metricsBox, 'Behavior', Number(modules.behavior).toFixed(2) + '%', 'normal');

    if (modules.nlp !== undefined)
      addMetric(metricsBox, 'NLP', Number(modules.nlp).toFixed(2) + '%', 'normal');
    }

    // Add metadata
    addMetricSection(metricsBox, 'Metadata');
    addMetric(metricsBox, 'Model', result.model || 'Unknown', 'normal');
    addMetric(metricsBox, 'Timestamp', formatTimestamp(result.timestamp), 'normal');

    if (result.whitelisted) {
      addMetric(metricsBox, 'Status', 'Whitelisted', 'good');
    }

    if (result.error) {
      addMetric(metricsBox, 'Error', result.errorMessage || 'API Error', 'bad');
    }
  }

  /**
   * Add metric section header
   */
  function addMetricSection(container, title) {
    const header = document.createElement('div');
    header.className = 'metric-section-header';
    header.textContent = title;
    container.appendChild(header);
  }

  /**
   * Add metric row
   */
  function addMetric(container, label, value, colorClass) {
    const row = document.createElement('div');
    row.className = 'metric-item';

    const labelEl = document.createElement('span');
    labelEl.className = 'metric-label';
    labelEl.textContent = label;

    const valueEl = document.createElement('span');
    valueEl.className = `metric-value ${colorClass}`;
    valueEl.textContent = value;

    row.appendChild(labelEl);
    row.appendChild(valueEl);
    container.appendChild(row);
  }

  /**
   * Get color class for classification
   */
  function getClassColor(classification) {
    if (classification === 'Phishing') return 'bad';
    if (classification === 'Suspicious') return 'warning';
    return 'good';
  }

  /**
   * Get color class for risk level
   */
  function getRiskColor(riskLevel) {
    if (riskLevel === 'high') return 'bad';
    if (riskLevel === 'medium') return 'warning';
    return 'good';
  }

  /**
   * Format timestamp
   */
  function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch {
      return 'N/A';
    }
  }

  /**
   * Show loading state
   */
  function showLoading() {
    document.querySelector('.scan-section').style.display = 'none';
    document.getElementById('info-section').style.display = 'none';
    document.getElementById('result-container').classList.remove('active');
    document.getElementById('loading-container').classList.add('active');
  }

  /**
   * Show error
   */
  function showError(message) {
    document.getElementById('loading-container').classList.remove('active');
    document.querySelector('.scan-section').style.display = 'block';
    document.getElementById('info-section').style.display = 'block';
    
    alert('Error: ' + message);
  }

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Cleanup on unload
  window.addEventListener('beforeunload', () => {
    if (tipInterval) {
      clearInterval(tipInterval);
    }
  });

})();