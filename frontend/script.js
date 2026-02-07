/**
 * PhishGuard AI - Main Application Script
 * FULLY CORRECTED VERSION - All issues fixed
 */

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------
const CONFIG = {
    STORAGE_KEY: "phishguard_history",
    MAX_HISTORY: 10,
    THEMES: ["cyber", "dark", "light"],
    ANIMATION_DURATION: 1000
};

// ------------------------------------------------------------------
// DOM ELEMENTS
// ------------------------------------------------------------------
const elements = {
    scanBtn: document.getElementById("scanBtn"),
    urlInput: document.getElementById("urlInput"),
    urlPreview: document.getElementById("urlPreview"),
    loading: document.getElementById("loading"),
    loadingStage: document.getElementById("loadingStage"),
    loadingTime: document.getElementById("loadingTime"),
    progressBar: document.getElementById("progressBar"),
    resultCard: document.getElementById("resultCard"),
    status: document.getElementById("status"),
    confidenceValue: document.getElementById("confidenceValue"),
    progressCircle: document.getElementById("progressCircle"),
    riskLevel: document.getElementById("riskLevel"),
    riskFactors: document.getElementById("riskFactors"),
    scannedUrl: document.getElementById("scannedUrl"),
    modelName: document.getElementById("modelName"),
    scanDuration: document.getElementById("scanDuration"),
    domainAge: document.getElementById("domainAge"),
    httpsStatus: document.getElementById("httpsStatus"),
    urlLength: document.getElementById("urlLength"),
    totalScans: document.getElementById("totalScans"),
    threatsBlocked: document.getElementById("threatsBlocked"),
    toast: document.getElementById("toast"),
    historySidebar: document.getElementById("historySidebar"),
    historyList: document.getElementById("historyList"),
    detailsContent: document.getElementById("detailsContent"),
    detailsToggle: document.getElementById("detailsToggle"),
    avgScanTime: document.getElementById("avgScanTime"),
    featuresChart: document.getElementById("featuresChart")
};

// ------------------------------------------------------------------
// STATE MANAGEMENT
// ------------------------------------------------------------------
let state = {
    currentScan: null,
    scanStartTime: null,
    history: [],
    stats: {
        totalScans: 0,
        threatsBlocked: 0,
        totalScanTime: 0
    },
    chart: null
};

// ------------------------------------------------------------------
// INITIALIZATION
// ------------------------------------------------------------------
function init() {
    loadHistory();
    loadStats();
    updateStatsDisplay();
    attachEventListeners();
    setupKeyboardShortcuts();
    
    console.log('✅ PhishGuard AI initialized');
}

// ------------------------------------------------------------------
// EVENT LISTENERS
// ------------------------------------------------------------------
function attachEventListeners() {
    // Main scan button
    elements.scanBtn.addEventListener("click", handleScan);
    
    // URL input
    elements.urlInput.addEventListener("input", handleUrlInput);
    elements.urlInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") handleScan();
    });
    
    // Quick test buttons - ONLY set URL, don't auto-scan
    document.querySelectorAll(".quick-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            elements.urlInput.value = btn.dataset.url;
            elements.urlInput.focus();
        });
    });
    
    // UI controls
    document.getElementById("themeToggle")?.addEventListener("click", cycleTheme);
    document.getElementById("historyToggle")?.addEventListener("click", toggleHistory);
    document.getElementById("closeHistory")?.addEventListener("click", toggleHistory);
    document.getElementById("clearHistory")?.addEventListener("click", clearHistory);
    document.getElementById("copyBtn")?.addEventListener("click", copyResult);
    document.getElementById("shareBtn")?.addEventListener("click", shareResult);
    document.getElementById("exportBtn")?.addEventListener("click", exportResult);
    elements.detailsToggle?.addEventListener("click", toggleDetails);
}

// ------------------------------------------------------------------
// KEYBOARD SHORTCUTS
// ------------------------------------------------------------------
function setupKeyboardShortcuts() {
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            handleScan();
        }
        
        if (e.key === "Escape") {
            elements.historySidebar?.classList.add("hidden");
        }
    });
}

// ------------------------------------------------------------------
// URL INPUT HANDLER
// ------------------------------------------------------------------
function handleUrlInput(e) {
    const url = e.target.value.trim();
    
    if (!url) {
        elements.urlPreview.textContent = "";
        elements.urlPreview.classList.remove("show", "error");
        return;
    }
    
    try {
        const parsed = new URL(url);
        elements.urlPreview.innerHTML = `
            <i class="fas fa-${parsed.protocol === 'https:' ? 'lock' : 'unlock'}"></i>
            ${parsed.hostname}
        `;
        elements.urlPreview.classList.add("show");
        elements.urlPreview.classList.remove("error");
    } catch {
        elements.urlPreview.textContent = "⚠️ Invalid URL format";
        elements.urlPreview.classList.add("show", "error");
    }
}

// ------------------------------------------------------------------
// SCAN HANDLER - CRITICAL SECTION
// ------------------------------------------------------------------
async function handleScan() {
    const url = elements.urlInput.value.trim();
    
    if (!url) {
        showToast("Please enter a URL", "error");
        return;
    }
    
    if (!isValidURL(url)) {
        showToast("Invalid URL format. Include http:// or https://", "error");
        return;
    }
    
    // Reset UI before scan
    resetResultUI();
    state.scanStartTime = Date.now();
    showLoading();
    simulateProgress();
    
    try {
        console.log('🔍 Starting scan for:', url);
        
        // Check if authenticated to use the right endpoint
        const token = localStorage.getItem('token');
        let data;
        
        if (token && window.API.isAuthenticated()) {
            console.log('Using authenticated scan endpoint');
            data = await window.API.scanURLAuthenticated(url);
        } else {
            console.log('Using public scan endpoint');
            data = await window.API.scanURL(url);
        }
        
        console.log('✅ Scan complete, received data:', data);
        
        // CRITICAL: Store scan data exactly as received from API
        state.currentScan = {
            url: data.url,
            classification: data.classification,
            confidence: data.confidence,
            riskLevel: data.riskLevel,
            model: data.model,
            metrics: data.metrics,
            timestamp: data.timestamp
        };
        
        // Display result using API data
        await displayResult(data);
        
        // Update stats and history
        updateStats(data);
        saveToHistory(state.currentScan);
        
        showToast("Scan completed successfully", "success");
        
    } catch (error) {
        console.error('❌ Scan failed:', error);
        showToast("Scan failed: " + error.message, "error");
    } finally {
        hideLoading();
    }
}

// ------------------------------------------------------------------
// DISPLAY RESULT - FULLY FIXED VERSION
// ------------------------------------------------------------------
async function displayResult(data) {
    console.log('📊 Displaying result:', data);
    
    const scanTime = ((Date.now() - state.scanStartTime) / 1000).toFixed(2);
    
    // Update scanned URL
    elements.scannedUrl.textContent = data.url;
    
    // ================================================================
    // FIX 1: PROPER STATUS BADGE WITH CORRECT CSS CLASSES
    // ================================================================
    const classification = data.classification;
    let statusClass, statusIcon, statusText;
    
    // Remove all previous status classes
    elements.status.className = 'status';
    
    // Map backend classification to UI
    if (classification === 'Phishing' || classification === 'PHISHING') {
        statusClass = 'danger';
        statusIcon = 'fa-exclamation-triangle';
        statusText = 'PHISHING';
    } else if (classification === 'Legitimate' || classification === 'LEGITIMATE' || classification === 'Safe' || classification === 'SAFE') {
        statusClass = 'safe';
        statusIcon = 'fa-check-circle';
        statusText = 'SAFE';
    } else if (classification === 'Suspicious' || classification === 'SUSPICIOUS') {
        statusClass = 'warning';
        statusIcon = 'fa-exclamation-circle';
        statusText = 'SUSPICIOUS';
    } else {
        statusClass = 'warning';
        statusIcon = 'fa-question-circle';
        statusText = classification.toUpperCase();
    }
    
    // Apply the status class
    elements.status.classList.add(statusClass);
    elements.status.innerHTML = `<i class="fas ${statusIcon}"></i> ${statusText}`;
    
    // Update confidence meter
    let confidencePercent;
    if (data.confidence <= 1) {
        confidencePercent = Math.round(data.confidence * 100);
    } else {
        confidencePercent = Math.round(data.confidence);
    }
    
    elements.confidenceValue.textContent = confidencePercent;
    
    // Animate circular progress
    const circumference = 2 * Math.PI * 70;
    const offset = circumference - (confidencePercent / 100) * circumference;
    elements.progressCircle.style.strokeDasharray = circumference;
    elements.progressCircle.style.strokeDashoffset = offset;
    
    // Color the progress circle based on status
    if (statusClass === 'danger') {
        elements.progressCircle.style.stroke = '#ff006e';
    } else if (statusClass === 'warning') {
        elements.progressCircle.style.stroke = '#ffbe0b';
    } else {
        elements.progressCircle.style.stroke = '#00ff41';
    }
    
    // ================================================================
    // FIX 2: PROPER RISK LEVEL CALCULATION
    // ================================================================
    let riskLevel = 'Unknown';
    
    // Try to get risk level from various possible sources
    if (data.riskLevel && data.riskLevel !== 'Unknown') {
        riskLevel = data.riskLevel;
    } else if (data.metrics?.riskLevel && data.metrics.riskLevel !== 'Unknown') {
        riskLevel = data.metrics.riskLevel;
    } else if (data.risk_level) {
        riskLevel = data.risk_level;
    } else {
        // Calculate risk level based on classification and confidence
        if (classification === 'Phishing' || classification === 'PHISHING') {
            if (confidencePercent >= 90) {
                riskLevel = 'Critical';
            } else if (confidencePercent >= 70) {
                riskLevel = 'High';
            } else {
                riskLevel = 'Medium';
            }
        } else if (classification === 'Suspicious' || classification === 'SUSPICIOUS') {
            riskLevel = 'Medium';
        } else {
            riskLevel = 'Low';
        }
    }
    
    elements.riskLevel.textContent = riskLevel;
    
    // Update other metrics
    elements.httpsStatus.textContent = data.metrics?.https ? 'Yes' : 'No';
    elements.urlLength.textContent = data.metrics?.urlLength || data.url?.length || 0;
    elements.domainAge.textContent = data.metrics?.domainAge || 'Unknown';
    elements.modelName.textContent = data.model || 'ML Classifier';
    elements.scanDuration.textContent = scanTime + 's';
    
    // ================================================================
    // FIX 3: COMPREHENSIVE RISK FACTORS ANALYSIS
    // ================================================================
    displayRiskFactors(data, classification, confidencePercent);
    
    // ================================================================
    // FIX 4: DETAILED ANALYSIS CHART
    // ================================================================
    displayDetailedAnalysis(data);
    
    // Show result card
    elements.resultCard.classList.remove("hidden");
    
    // Animate in
    setTimeout(() => {
        elements.resultCard.style.opacity = "1";
        elements.resultCard.style.transform = "translateY(0)";
    }, 50);
}

// ------------------------------------------------------------------
// FIX: COMPREHENSIVE RISK FACTORS DISPLAY
// ------------------------------------------------------------------
function displayRiskFactors(data, classification, confidencePercent) {
    if (!elements.riskFactors) return;
    
    const factors = [];
    const url = data.url;
    const metrics = data.metrics || {};
    const features = metrics.features || {};
    
    // Analyze URL structure
    try {
        const urlObj = new URL(url);
        
        // Check for IP address in URL
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
            factors.push({ 
                icon: 'fa-network-wired', 
                text: 'URL uses IP address instead of domain name',
                risk: 'high'
            });
        }
        
        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw'];
        if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
            factors.push({ 
                icon: 'fa-globe', 
                text: 'Uses suspicious top-level domain',
                risk: 'high'
            });
        }
        
        // Check for long URL
        if (url.length > 75) {
            factors.push({ 
                icon: 'fa-ruler-horizontal', 
                text: `Unusually long URL (${url.length} characters)`,
                risk: 'medium'
            });
        }
        
        // Check for many subdomains
        const subdomainCount = urlObj.hostname.split('.').length - 2;
        if (subdomainCount > 2) {
            factors.push({ 
                icon: 'fa-sitemap', 
                text: `Multiple subdomains detected (${subdomainCount})`,
                risk: 'medium'
            });
        }
        
        // Check HTTPS
        if (urlObj.protocol === 'http:') {
            factors.push({ 
                icon: 'fa-unlock', 
                text: 'Not using secure HTTPS protocol',
                risk: 'medium'
            });
        }
        
        // Check for suspicious keywords
        const suspiciousKeywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 'confirm', 'signin'];
        const hasKeyword = suspiciousKeywords.some(keyword => url.toLowerCase().includes(keyword));
        if (hasKeyword && (classification === 'Phishing' || classification === 'PHISHING')) {
            factors.push({ 
                icon: 'fa-key', 
                text: 'Contains suspicious authentication-related keywords',
                risk: 'high'
            });
        }
        
        // Check for @ symbol (can hide real domain)
        if (url.includes('@')) {
            factors.push({ 
                icon: 'fa-at', 
                text: 'Contains @ symbol (domain masking)',
                risk: 'high'
            });
        }
        
        // Check for many hyphens
        const hyphenCount = urlObj.hostname.split('-').length - 1;
        if (hyphenCount > 3) {
            factors.push({ 
                icon: 'fa-minus', 
                text: 'Excessive use of hyphens in domain',
                risk: 'medium'
            });
        }
        
    } catch (e) {
        console.error('Error parsing URL for risk analysis:', e);
    }
    
    // If PHISHING with high confidence, emphasize danger
    if (classification === 'Phishing' || classification === 'PHISHING') {
        if (confidencePercent >= 90) {
            factors.unshift({ 
                icon: 'fa-skull-crossbones', 
                text: `High confidence phishing detection (${confidencePercent}%)`,
                risk: 'critical'
            });
        }
    }
    
    // If legitimate, show positive factors
    if (classification === 'Legitimate' || classification === 'LEGITIMATE' || classification === 'Safe') {
        try {
            const urlObj = new URL(url);
            
            if (urlObj.protocol === 'https:') {
                factors.push({ 
                    icon: 'fa-lock', 
                    text: 'Secure HTTPS connection',
                    risk: 'low'
                });
            }
            
            if (url.length < 50) {
                factors.push({ 
                    icon: 'fa-check', 
                    text: 'Normal URL length',
                    risk: 'low'
                });
            }
            
            const trustedDomains = ['google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com'];
            if (trustedDomains.some(domain => urlObj.hostname.includes(domain))) {
                factors.push({ 
                    icon: 'fa-shield-alt', 
                    text: 'Recognized trusted domain',
                    risk: 'low'
                });
            }
        } catch (e) {
            // Ignore parse errors for positive factors
        }
    }
    
    // Display factors
    if (factors.length > 0) {
        elements.riskFactors.innerHTML = factors.map(f => {
            const riskClass = f.risk === 'critical' ? 'critical' : 
                            f.risk === 'high' ? 'high' : 
                            f.risk === 'medium' ? 'medium' : 'low';
            
            return `
                <div class="risk-factor ${riskClass}">
                    <i class="fas ${f.icon}"></i>
                    <span>${f.text}</span>
                </div>
            `;
        }).join('');
    } else {
        elements.riskFactors.innerHTML = `
            <div class="risk-factor low">
                <i class="fas fa-info-circle"></i>
                <span>No specific risk factors detected</span>
            </div>
        `;
    }
}

// ------------------------------------------------------------------
// FIX: DETAILED ANALYSIS CHART - CORRECTED VERSION
// ------------------------------------------------------------------
function displayDetailedAnalysis(data) {
    if (!elements.featuresChart) return;
    
    const metrics = data.metrics || {};
    const features = metrics.features || {};
    
    // Destroy existing chart if any
    if (state.chart) {
        state.chart.destroy();
    }
    
    // Prepare chart data with better labels and values
    const chartData = [];
    
    // Add confidence first (most important)
    let confidencePercent = data.confidence <= 1 ? data.confidence * 100 : data.confidence;
    chartData.push({
        label: 'ML Confidence',
        value: confidencePercent,
        color: 'rgba(139, 0, 139, 0.7)'
    });
    
    // Add URL analysis features
    if (features.url_length !== undefined) {
        // Normalize URL length to percentage (assuming 100 chars = 100%)
        const normalizedLength = Math.min((features.url_length / 100) * 100, 100);
        chartData.push({
            label: 'URL Length',
            value: normalizedLength,
            color: normalizedLength > 75 ? 'rgba(255, 0, 110, 0.7)' : 'rgba(0, 255, 65, 0.7)'
        });
    }
    
    if (features.has_https !== undefined) {
        chartData.push({
            label: 'HTTPS Security',
            value: features.has_https * 100,
            color: features.has_https ? 'rgba(0, 255, 65, 0.7)' : 'rgba(255, 0, 110, 0.7)'
        });
    }
    
    if (features.subdomain_count !== undefined) {
        // Normalize subdomain count (more than 3 is suspicious)
        const subdomainScore = Math.min((features.subdomain_count / 5) * 100, 100);
        chartData.push({
            label: 'Subdomain Count',
            value: subdomainScore,
            color: subdomainScore > 60 ? 'rgba(255, 190, 11, 0.7)' : 'rgba(0, 255, 65, 0.7)'
        });
    }
    
    if (features.has_ip !== undefined) {
        chartData.push({
            label: 'IP in URL',
            value: features.has_ip * 100,
            color: features.has_ip ? 'rgba(255, 0, 110, 0.7)' : 'rgba(0, 255, 65, 0.7)'
        });
    }
    
    if (features.has_suspicious_keywords !== undefined) {
        chartData.push({
            label: 'Suspicious Keywords',
            value: features.has_suspicious_keywords * 100,
            color: features.has_suspicious_keywords ? 'rgba(255, 190, 11, 0.7)' : 'rgba(0, 255, 65, 0.7)'
        });
    }
    
    // If no features, show at least confidence
    if (chartData.length === 0) {
        chartData.push({
            label: 'ML Confidence',
            value: confidencePercent,
            color: 'rgba(139, 0, 139, 0.7)'
        });
    }
    
    // Extract labels, values, and colors
    const labels = chartData.map(d => d.label);
    const values = chartData.map(d => d.value);
    const colors = chartData.map(d => d.color);
    
    // Create chart
    const ctx = elements.featuresChart.getContext('2d');
    
    state.chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Analysis Score (%)',
                data: values,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.7', '1')),
                borderWidth: 2,
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: 'y', // Horizontal bars
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: '#a0a0a0',
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#e8e8e8',
                        font: {
                            size: 12
                        }
                    },
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00ff41',
                    bodyColor: '#e8e8e8',
                    borderColor: '#00ff41',
                    borderWidth: 1,
                    padding: 12,
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            return context.parsed.x.toFixed(1) + '%';
                        }
                    }
                }
            }
        }
    });
}

// ------------------------------------------------------------------
// LOADING ANIMATIONS
// ------------------------------------------------------------------
function showLoading() {
    elements.loading.classList.remove("hidden");
    elements.scanBtn.disabled = true;
    elements.scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
}

function hideLoading() {
    elements.loading.classList.add("hidden");
    elements.scanBtn.disabled = false;
    elements.scanBtn.innerHTML = '<i class="fas fa-search"></i> <span>Scan Website</span>';
}

function simulateProgress() {
    const stages = [
        "Connecting to server...",
        "Extracting URL features...",
        "Running ML analysis...",
        "Analyzing risk factors...",
        "Finalizing report..."
    ];
    
    let progress = 0;
    let stageIndex = 0;
    
    const interval = setInterval(() => {
        progress += Math.random() * 20;
        if (progress > 90) progress = 90;
        
        elements.progressBar.style.width = progress + "%";
        
        if (stageIndex < stages.length) {
            elements.loadingStage.textContent = stages[stageIndex];
            stageIndex++;
        }
        
        const elapsed = ((Date.now() - state.scanStartTime) / 1000).toFixed(1);
        elements.loadingTime.textContent = elapsed + "s";
        
    }, 300);
    
    setTimeout(() => {
        clearInterval(interval);
        elements.progressBar.style.width = "100%";
    }, 2000);
}

// ------------------------------------------------------------------
// STATS MANAGEMENT
// ------------------------------------------------------------------
function updateStats(data) {
    state.stats.totalScans++;
    
    const classification = data.classification;
    if (classification === 'Phishing' || classification === 'PHISHING') {
        state.stats.threatsBlocked++;
    }
    
    const scanTime = (Date.now() - state.scanStartTime) / 1000;
    state.stats.totalScanTime += scanTime;
    
    saveStats();
    updateStatsDisplay();
}

function updateStatsDisplay() {
    elements.totalScans.textContent = state.stats.totalScans;
    elements.threatsBlocked.textContent = state.stats.threatsBlocked;
    
    if (state.stats.totalScans > 0) {
        const avgTime = (state.stats.totalScanTime / state.stats.totalScans).toFixed(1);
        elements.avgScanTime.textContent = avgTime + "s";
    }
}

function saveStats() {
    localStorage.setItem("phishguard_stats", JSON.stringify(state.stats));
}

function loadStats() {
    const saved = localStorage.getItem("phishguard_stats");
    if (saved) {
        state.stats = JSON.parse(saved);
    }
}

// ------------------------------------------------------------------
// HISTORY MANAGEMENT
// ------------------------------------------------------------------
function saveToHistory(scan) {
    state.history.unshift(scan);
    if (state.history.length > CONFIG.MAX_HISTORY) {
        state.history.pop();
    }
    localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(state.history));
    updateHistoryDisplay();
}

function loadHistory() {
    const saved = localStorage.getItem(CONFIG.STORAGE_KEY);
    if (saved) {
        state.history = JSON.parse(saved);
        updateHistoryDisplay();
    }
}

function updateHistoryDisplay() {
    elements.historyList.innerHTML = "";
    
    if (state.history.length === 0) {
        elements.historyList.innerHTML = '<div class="history-empty">No scans yet</div>';
        return;
    }
    
    state.history.forEach((scan) => {
        const div = document.createElement("div");
        div.className = "history-item";
        
        const classification = scan.classification;
        let statusClass;
        
        if (classification === 'Phishing' || classification === 'PHISHING') {
            statusClass = 'danger';
        } else if (classification === 'Suspicious' || classification === 'SUSPICIOUS') {
            statusClass = 'warning';
        } else {
            statusClass = 'safe';
        }
        
        const iconMap = {
            'danger': 'fa-exclamation-triangle',
            'warning': 'fa-exclamation-circle',
            'safe': 'fa-check-circle'
        };
        
        div.innerHTML = `
            <div class="history-icon ${statusClass}">
                <i class="fas ${iconMap[statusClass]}"></i>
            </div>
            <div class="history-details">
                <div class="history-url">${truncateUrl(scan.url)}</div>
                <div class="history-meta">
                    ${classification} • ${new Date(scan.timestamp).toLocaleString()}
                </div>
            </div>
        `;
        
        div.addEventListener("click", () => {
            elements.urlInput.value = scan.url;
            toggleHistory();
        });
        
        elements.historyList.appendChild(div);
    });
}

function clearHistory() {
    if (confirm("Clear all scan history?")) {
        state.history = [];
        localStorage.removeItem(CONFIG.STORAGE_KEY);
        updateHistoryDisplay();
        showToast("History cleared", "info");
    }
}

function toggleHistory() {
    elements.historySidebar?.classList.toggle("hidden");
}

// ------------------------------------------------------------------
// RESULT ACTIONS
// ------------------------------------------------------------------
function copyResult() {
    if (!state.currentScan) {
        showToast("No scan result to copy", "error");
        return;
    }
    
    const confidencePercent = state.currentScan.confidence <= 1 
        ? Math.round(state.currentScan.confidence * 100)
        : Math.round(state.currentScan.confidence);
    
    const text = `
PhishGuard AI Scan Result
URL: ${state.currentScan.url}
Status: ${state.currentScan.classification}
Confidence: ${confidencePercent}%
Risk Level: ${state.currentScan.riskLevel}
Timestamp: ${new Date(state.currentScan.timestamp).toLocaleString()}
    `.trim();
    
    navigator.clipboard.writeText(text).then(() => {
        showToast("Result copied to clipboard", "success");
    }).catch(() => {
        showToast("Failed to copy to clipboard", "error");
    });
}

// REPLACE shareResult() with:
function shareResult() {
    if (!state.currentScan) {
        showToast("No scan result to share", "error");
        return;
    }
    
    // Check authentication
    if (!isAuthenticated()) {
        showAuthModal('share', function() {
            shareResult(); // Retry after login
        });
        return;
    }
    
    // Proceed with share...
    if (navigator.share) {
        const confidencePercent = state.currentScan.confidence <= 1 
            ? Math.round(state.currentScan.confidence * 100)
            : Math.round(state.currentScan.confidence);
            
        navigator.share({
            title: "PhishGuard AI Scan Result",
            text: `PhishGuard AI: ${state.currentScan.url} is ${state.currentScan.classification} (${confidencePercent}% confidence)`,
            url: window.location.href
        }).catch(() => {
            showToast("Share cancelled", "info");
        });
    } else {
        showToast("Share not supported on this browser", "info");
    }
}

// REPLACE exportResult() with:
function exportResult() {
    if (!state.currentScan) {
        showToast("No scan result to export", "error");
        return;
    }
    
    // Check authentication
    if (!isAuthenticated()) {
        showAuthModal('export', function() {
            exportResult(); // Retry after login
        });
        return;
    }
    
    // Proceed with export...
    const exportData = {
        ...state.currentScan,
        exportedAt: new Date().toISOString(),
        exportedBy: JSON.parse(localStorage.getItem('user') || '{}').username || 'User'
    };
    
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishguard-scan-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast("Report exported successfully", "success");
}

// ------------------------------------------------------------------
// DETAILS TOGGLE
// ------------------------------------------------------------------
function toggleDetails() {
    elements.detailsContent?.classList.toggle("hidden");
    const icon = elements.detailsToggle?.querySelector("i");
    icon?.classList.toggle("fa-chevron-down");
    icon?.classList.toggle("fa-chevron-up");
}

// ------------------------------------------------------------------
// THEME MANAGEMENT
// ------------------------------------------------------------------
function cycleTheme() {
    const html = document.documentElement;
    const current = html.dataset.theme || "cyber";
    const index = CONFIG.THEMES.indexOf(current);
    const next = CONFIG.THEMES[(index + 1) % CONFIG.THEMES.length];
    
    html.dataset.theme = next;
    localStorage.setItem("phishguard_theme", next);
    
    const icon = document.querySelector("#themeToggle i");
    if (icon) {
        icon.className = next === "light" ? "fas fa-sun" : "fas fa-moon";
    }
    
    showToast(`Theme: ${next}`, "info");
}

// Load saved theme
const savedTheme = localStorage.getItem("phishguard_theme");
if (savedTheme) {
    document.documentElement.dataset.theme = savedTheme;
}

// ------------------------------------------------------------------
// TOAST NOTIFICATIONS
// ------------------------------------------------------------------
function showToast(message, type = "info") {
    elements.toast.textContent = message;
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove("hidden");
    
    setTimeout(() => {
        elements.toast.classList.add("hidden");
    }, 3000);
}

// ------------------------------------------------------------------
// UTILITIES
// ------------------------------------------------------------------
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function truncateUrl(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + "...";
}

function resetResultUI() {
    elements.resultCard.classList.add("hidden");
    elements.resultCard.style.opacity = "0";
    elements.resultCard.style.transform = "translateY(20px)";
    elements.progressBar.style.width = "0%";
    elements.urlPreview.classList.remove("show");
}

// ------------------------------------------------------------------
// INITIALIZE ON LOAD
// ------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", init);