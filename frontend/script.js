/**
 * PhishGuard AI - Frontend Script v6.1 (FIXED CHARTS + SYNTAX)
 *
 * SCORING POLICY:
 *   - Classification badge, confidence meter, and risk level are driven
 *     EXCLUSIVELY by the ML model score (result.modules.ml or
 *     result.ensemble_score which equals ml_score on the v6 backend).
 *   - The "Detailed Analysis" charts display all 5 module scores
 *     (ML, Lexical, Reputation, Behavior, NLP) for visualization.
 *   - Other module scores are informational ONLY and do NOT change
 *     the verdict shown to the user.
 *
 * CHART FIXES:
 *   - Multi-Module Detection: Now correctly extracts individual module scores
 *   - Ensemble Contribution: Now shows weighted influence, not raw scores
 */

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------
const CONFIG = {
    STORAGE_KEY:        "phishguard_history",
    MAX_HISTORY:        10,
    THEMES:             ["cyber", "dark", "light"],
    ANIMATION_DURATION: 1000,
    API_ENDPOINT:       "http://localhost:5000/api/scan-enhanced"
};

// ML-only thresholds (must match backend)
const ML_PHISHING_THRESHOLD   = 75;  // percent
const ML_SUSPICIOUS_THRESHOLD = 40;  // percent

// Module weights for ensemble calculation (must match backend)
const MODULE_WEIGHTS = {
    ml: 0.60,
    lexical: 0.15,
    reputation: 0.15,
    behavior: 0.05,
    nlp: 0.05
};

// ------------------------------------------------------------------
// DOM ELEMENTS
// ------------------------------------------------------------------
const elements = {
    scanBtn:         document.getElementById("scanBtn"),
    urlInput:        document.getElementById("urlInput"),
    urlPreview:      document.getElementById("urlPreview"),

    loading:         document.getElementById("loading"),
    loadingStage:    document.getElementById("loadingStage"),
    loadingTime:     document.getElementById("loadingTime"),
    progressBar:     document.getElementById("progressBar"),

    resultCard:      document.getElementById("resultCard"),
    status:          document.getElementById("status"),
    confidenceValue: document.getElementById("confidenceValue"),
    progressCircle:  document.getElementById("progressCircle"),
    riskLevel:       document.getElementById("riskLevel"),
    riskFactors:     document.getElementById("riskFactors"),

    scannedUrl:      document.getElementById("scannedUrl"),
    modelName:       document.getElementById("modelName"),
    scanDuration:    document.getElementById("scanDuration"),
    domainAge:       document.getElementById("domainAge"),
    httpsStatus:     document.getElementById("httpsStatus"),
    urlLength:       document.getElementById("urlLength"),

    totalScans:      document.getElementById("totalScans"),
    threatsBlocked:  document.getElementById("threatsBlocked"),
    avgScanTime:     document.getElementById("avgScanTime"),

    toast:           document.getElementById("toast"),
    historySidebar:  document.getElementById("historySidebar"),
    historyList:     document.getElementById("historyList"),

    detailsContent:  document.getElementById("detailsContent"),
    detailsToggle:   document.getElementById("detailsToggle"),

    featuresChart:   document.getElementById("featuresChart"),

    guideBtn:        document.getElementById("guideBtn"),
    guideModal:      document.getElementById("guideModal"),
    guideClose:      document.getElementById("guideClose"),

    detectionChart:  document.getElementById("detectionChart"),
    ensembleChart:   document.getElementById("ensembleChart")
};

// ------------------------------------------------------------------
// STATE
// ------------------------------------------------------------------
let state = {
    currentScan:   null,
    scanStartTime: null,
    history:       [],
    stats: {
        totalScans:    0,
        threatsBlocked:0,
        totalScanTime: 0
    },
    charts: {
        features:  null,
        detection: null,
        ensemble:  null
    }
};

// ------------------------------------------------------------------
// INIT
// ------------------------------------------------------------------
function init() {
    loadHistory();
    loadStats();
    updateStatsDisplay();
    attachEventListeners();
    setupKeyboardShortcuts();
    loadSavedTheme();
    console.log("✅ PhishGuard AI v6.1 initialized (ML-only verdict + FIXED CHARTS)");
}

// ------------------------------------------------------------------
// THEME
// ------------------------------------------------------------------
function loadSavedTheme() {
    const saved = localStorage.getItem("phishguard_theme");
    if (saved) {
        document.documentElement.dataset.theme = saved;
        const icon = document.querySelector("#themeToggle i");
        if (icon) icon.className = saved === "light" ? "fas fa-sun" : "fas fa-moon";
    }
}

function cycleTheme() {
    const html    = document.documentElement;
    const current = html.dataset.theme || "cyber";
    const index   = CONFIG.THEMES.indexOf(current);
    const next    = CONFIG.THEMES[(index + 1) % CONFIG.THEMES.length];

    html.dataset.theme = next;
    localStorage.setItem("phishguard_theme", next);

    const icon = document.querySelector("#themeToggle i");
    if (icon) icon.className = next === "light" ? "fas fa-sun" : "fas fa-moon";

    showToast(`Theme: ${next}`, "info");
}

// ------------------------------------------------------------------
// EVENT LISTENERS
// ------------------------------------------------------------------
function attachEventListeners() {
    elements.scanBtn.addEventListener("click", handleScan);
    elements.urlInput.addEventListener("input", handleUrlInput);
    elements.urlInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") handleScan();
    });

    document.querySelectorAll(".quick-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            elements.urlInput.value = btn.dataset.url;
            elements.urlInput.focus();
        });
    });

    document.getElementById("themeToggle")?.addEventListener("click", cycleTheme);

    document.getElementById("toggleHistoryBtn")?.addEventListener("click", toggleHistory);
    document.getElementById("historyToggle")?.addEventListener("click", toggleHistory);
    document.getElementById("closeHistory")?.addEventListener("click", toggleHistory);

    document.getElementById("clearHistoryBtn")?.addEventListener("click", clearHistory);
    document.getElementById("clearHistory")?.addEventListener("click", clearHistory);

    document.getElementById("copyBtn")?.addEventListener("click", copyResult);
    document.getElementById("shareBtn")?.addEventListener("click", shareResult);
    document.getElementById("exportBtn")?.addEventListener("click", exportResult);

    elements.detailsToggle?.addEventListener("click", toggleDetails);

    elements.guideBtn?.addEventListener("click", openGuideModal);
    elements.guideClose?.addEventListener("click", closeGuideModal);
    elements.guideModal?.addEventListener("click", (e) => {
        if (e.target === elements.guideModal) closeGuideModal();
    });
}

// ------------------------------------------------------------------
// KEYBOARD SHORTCUTS
// ------------------------------------------------------------------
function setupKeyboardShortcuts() {
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            handleScan();
        }
        if (e.key === "Escape") {
            closeGuideModal();
            elements.historySidebar?.classList.add("hidden");
        }
    });
}

// ------------------------------------------------------------------
// GUIDE MODAL
// ------------------------------------------------------------------
function openGuideModal() {
    if (elements.guideModal) {
        elements.guideModal.classList.add("active");
        document.body.style.overflow = "hidden";
    }
}
function closeGuideModal() {
    if (elements.guideModal) {
        elements.guideModal.classList.remove("active");
        document.body.style.overflow = "";
    }
}

// ------------------------------------------------------------------
// URL INPUT HANDLER
// ------------------------------------------------------------------
function handleUrlInput(e) {
    const url = e.target.value.trim();
    if (!url) {
        if (elements.urlPreview) {
            elements.urlPreview.textContent = "";
            elements.urlPreview.classList.remove("show", "error");
        }
        return;
    }
    try {
        const parsed = new URL(url);
        if (elements.urlPreview) {
            elements.urlPreview.innerHTML = `${parsed.hostname}`;
            elements.urlPreview.classList.add("show");
            elements.urlPreview.classList.remove("error");
        }
    } catch {
        if (elements.urlPreview) {
            elements.urlPreview.textContent = "⚠️ Invalid URL format";
            elements.urlPreview.classList.add("show", "error");
        }
    }
}

// ------------------------------------------------------------------
// MAIN SCAN HANDLER
// ------------------------------------------------------------------
async function handleScan() {
    const url = elements.urlInput.value.trim();
    if (!url) { showToast("Please enter a URL to scan", "warning"); elements.urlInput.focus(); return; }
    if (!isValidURL(url)) { showToast("Invalid URL format. Include http:// or https://", "error"); return; }

    resetResultUI();
    state.scanStartTime = Date.now();
    showLoading();
    simulateProgress();

    try {
        let data;
        if (
            typeof window.API !== "undefined" &&
            typeof window.API.isAuthenticated === "function" &&
            window.API.isAuthenticated()
        ) {
            data = await window.API.scanURLAuthenticated(url);
        } else if (
            typeof window.API !== "undefined" &&
            typeof window.API.scanURL === "function"
        ) {
            data = await window.API.scanURL(url);
        } else {
            data = await scanUrlDirect(url);
        }

        const scanDuration = Date.now() - state.scanStartTime;
        displayResult(data, scanDuration);
        saveToHistory(data, scanDuration);
        updateStats(data);
        showToast("Scan completed successfully", "success");

    } catch (error) {
        console.error("❌ Scan failed:", error);
        showToast("Scan failed: " + (error.message || "Please try again."), "error");
    } finally {
        hideLoading();
    }
}

async function scanUrlDirect(url) {
    const response = await fetch(CONFIG.API_ENDPOINT, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ url })
    });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`);
    }
    return await response.json();
}

// ------------------------------------------------------------------
// EXTRACT MODULE SCORES FROM RESPONSE - FIXED SYNTAX ERROR
// Returns object with all module scores in 0-100 percentage format
// ------------------------------------------------------------------
function extractModuleScores(data) {
    const toPercent = (v) => {
        if (v == null) return 0;
        return v <= 1 ? Math.round(v * 100) : Math.round(v);
    };

    console.log("DEBUG DATA STRUCTURE:", data);

    // 1️⃣ Internal engine
    if (data.modules && typeof data.modules === "object") {
        return {
            ml:         toPercent(data.modules.ml),
            lexical:    toPercent(data.modules.lexical),
            reputation: toPercent(data.modules.reputation),
            behavior:   toPercent(data.modules.behavior),
            nlp:        toPercent(data.modules.nlp)
        };
    }

    // 2️⃣ Enhanced endpoint (external ensemble)
    if (data.ensemble_modules && typeof data.ensemble_modules === "object") {
        return {
            ml:         toPercent(data.ensemble_modules?.ml_model?.score),
            lexical:    toPercent(data.ensemble_modules?.lexical?.score),
            reputation: toPercent(data.ensemble_modules?.reputation?.score),
            behavior:   toPercent(data.ensemble_modules?.behavior?.score),
            nlp:        toPercent(data.ensemble_modules?.nlp?.score)
        };
    }

    // 3️⃣ Fallback
    console.warn("⚠️ Could not extract module scores");
    return { ml: 0, lexical: 0, reputation: 0, behavior: 0, nlp: 0 };
}

// ------------------------------------------------------------------
// EXTRACT ML SCORE FROM RESPONSE
// Returns a 0-100 percentage based on the ML model score only.
// ------------------------------------------------------------------
function extractMLScore(data) {
    // Prefer modules.ml (explicit ML score from backend)
    const modules = data.modules || data.ensemble_modules || {};
    let mlScore = null;

    if (typeof modules.ml === 'number') {
        mlScore = modules.ml <= 1 ? modules.ml * 100 : modules.ml;
    } else if (typeof modules.ml_model === 'object' && modules.ml_model.score != null) {
        const s = modules.ml_model.score;
        mlScore = s <= 1 ? s * 100 : s;
    } else if (data.ml_confidence != null) {
        mlScore = data.ml_confidence <= 1 ? data.ml_confidence * 100 : data.ml_confidence;
    } else {
        // Fallback: ensemble_score equals ml_score on v6 backend
        const es = data.ensemble_score || data.confidence || 0;
        mlScore = es <= 1 ? es * 100 : es;
    }

    return Math.round(mlScore);
}

// ------------------------------------------------------------------
// DISPLAY RESULT
// Classification badge / confidence / risk level use ML score only.
// All module scores are passed to the charts for visualization.
// ------------------------------------------------------------------
function displayResult(data, scanDuration) {
    const scanTime = scanDuration
        ? (scanDuration / 1000).toFixed(2) + "s"
        : ((Date.now() - state.scanStartTime) / 1000).toFixed(2) + "s";

    elements.scannedUrl.textContent = data.url;

    // ── ML-only confidence ──────────────────────────────────────────
    const mlConfidencePct = extractMLScore(data);

    // ── Classification from ML score ───────────────────────────────
    let statusClass, statusIcon, statusText;
    if (mlConfidencePct >= ML_PHISHING_THRESHOLD) {
        statusClass = "danger";
        statusIcon  = "fa-exclamation-triangle";
        statusText  = "PHISHING";
    } else if (mlConfidencePct >= ML_SUSPICIOUS_THRESHOLD) {
        statusClass = "warning";
        statusIcon  = "fa-exclamation-circle";
        statusText  = "SUSPICIOUS";
    } else {
        statusClass = "safe";
        statusIcon  = "fa-check-circle";
        statusText  = "SAFE";
    }

    elements.status.className = "status";
    elements.status.classList.add(statusClass);
    elements.status.innerHTML = `<i class="fas ${statusIcon}"></i> ${statusText}`;

    // ── Confidence meter — ML only ──────────────────────────────────
    elements.confidenceValue.textContent = mlConfidencePct;

    const circumference = 2 * Math.PI * 70;
    const offset = circumference - (mlConfidencePct / 100) * circumference;
    elements.progressCircle.style.strokeDasharray  = `${circumference} ${circumference}`;
    elements.progressCircle.style.strokeDashoffset = circumference;
    setTimeout(() => {
        elements.progressCircle.style.strokeDashoffset = offset;
        elements.progressCircle.style.stroke =
            statusClass === "danger"  ? "#ff006e" :
            statusClass === "warning" ? "#ffbe0b" : "#00ff41";
    }, 100);

    // ── Risk level ──────────────────────────────────────────────────
    const riskLevel = calculateRiskLevel(statusClass, mlConfidencePct);
    elements.riskLevel.textContent = riskLevel;

    // ── Metrics ─────────────────────────────────────────────────────
    elements.httpsStatus.textContent  = data.metrics?.https ? "Yes ✓" : "No ✗";
    elements.urlLength.textContent    = data.metrics?.urlLength ?? data.metrics?.url_length ?? data.url?.length ?? "N/A";
    elements.domainAge.textContent    = data.metrics?.domainAge ?? data.metrics?.domain_age ?? "Unknown";
    elements.modelName.textContent    = data.model || "ML Classifier";
    elements.scanDuration.textContent = scanTime;

    // ── Risk factors ────────────────────────────────────────────────
    displayRiskFactors(data, statusClass, mlConfidencePct);

    // ── Charts: show ALL module scores for visualization ────────────
    createEnhancedDetectionChart(data);
    createEnsembleContributionChart(data);
    displayDetailedAnalysis(data, mlConfidencePct);

    // ── Store current scan ──────────────────────────────────────────
    state.currentScan = {
        url:            data.url,
        classification: statusText,
        confidence:     mlConfidencePct,
        riskLevel:      riskLevel,
        model:          data.model || "ML Classifier",
        metrics:        data.metrics || {},
        timestamp:      data.timestamp || new Date().toISOString()
    };

    elements.resultCard.classList.remove("hidden");
    elements.resultCard.style.opacity   = "0";
    elements.resultCard.style.transform = "translateY(20px)";
    elements.resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    setTimeout(() => {
        elements.resultCard.style.opacity   = "1";
        elements.resultCard.style.transform = "translateY(0)";
    }, 50);
}

// ------------------------------------------------------------------
// RISK LEVEL CALCULATOR  (ML score only)
// ------------------------------------------------------------------
function calculateRiskLevel(statusClass, confidencePct) {
    if (statusClass === "danger") {
        if (confidencePct >= 90) return "Critical";
        if (confidencePct >= 70) return "High";
        return "Medium";
    }
    if (statusClass === "warning") return "Medium";
    return "Low";
}

// ------------------------------------------------------------------
// RISK FACTORS
// ------------------------------------------------------------------
function displayRiskFactors(data, statusClass, confidencePct) {
    if (!elements.riskFactors) return;
    const factors = [];
    const url = data.url;

    // Backend-supplied factors
    const backendFactors =
        data.risk_factors ||
        data.ml_prediction?.risk_factors ||
        [];
    backendFactors.forEach(text => {
        factors.push({ icon: "fa-exclamation", text, risk: "high" });
    });

    // Client-side URL analysis
    try {
        const urlObj = new URL(url);

        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname))
            factors.push({ icon: "fa-network-wired", text: "URL uses IP address instead of domain name", risk: "high" });

        const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"];
        if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld)))
            factors.push({ icon: "fa-globe", text: "Uses suspicious top-level domain", risk: "high" });

        if (url.length > 75)
            factors.push({ icon: "fa-ruler-horizontal", text: `Unusually long URL (${url.length} characters)`, risk: "medium" });

        const subdomainCount = urlObj.hostname.split(".").length - 2;
        if (subdomainCount > 2)
            factors.push({ icon: "fa-sitemap", text: `Multiple subdomains detected (${subdomainCount})`, risk: "medium" });

        if (urlObj.protocol === "http:")
            factors.push({ icon: "fa-unlock", text: "Not using secure HTTPS protocol", risk: "medium" });

        const suspiciousKeywords = ["login","verify","account","update","secure","banking","confirm","signin"];
        if (suspiciousKeywords.some(kw => url.toLowerCase().includes(kw)) && statusClass === "danger")
            factors.push({ icon: "fa-key", text: "Contains suspicious authentication-related keywords", risk: "high" });

        if (url.includes("@"))
            factors.push({ icon: "fa-at", text: "Contains @ symbol (potential domain masking)", risk: "high" });

        const hyphenCount = urlObj.hostname.split("-").length - 1;
        if (hyphenCount > 3)
            factors.push({ icon: "fa-minus", text: "Excessive use of hyphens in domain", risk: "medium" });

        if (statusClass === "safe") {
            if (urlObj.protocol === "https:")
                factors.push({ icon: "fa-lock", text: "Secure HTTPS connection", risk: "low" });
            if (url.length < 50)
                factors.push({ icon: "fa-check", text: "Normal URL length", risk: "low" });
            const trustedDomains = ["google.com","github.com","microsoft.com","apple.com","amazon.com"];
            if (trustedDomains.some(d => urlObj.hostname.includes(d)))
                factors.push({ icon: "fa-shield-alt", text: "Recognised trusted domain", risk: "low" });
        }
    } catch (e) {
        console.error("URL parse error in risk analysis:", e);
    }

    if (statusClass === "danger" && confidencePct >= 90) {
        factors.unshift({
            icon: "fa-skull-crossbones",
            text: `High-confidence phishing detection (${confidencePct}%)`,
            risk: "critical"
        });
    }

    if (factors.length === 0) {
        elements.riskFactors.innerHTML =
            `<li class="no-factors"><span class="factor-icon">✓</span> No specific risk factors identified</li>`;
        return;
    }

    elements.riskFactors.innerHTML = factors.map(f => `
        <li class="risk-factor ${f.risk}">
            <i class="fas ${f.icon} factor-icon"></i>
            <span>${f.text}</span>
        </li>
    `).join("");
}

// ------------------------------------------------------------------
// ENHANCED DETECTION CHART - FIXED
// Shows REAL independent module scores, not duplicate ML scores
// ------------------------------------------------------------------
function createEnhancedDetectionChart(result) {
    const canvas = elements.detectionChart;
    if (!canvas) return;

    if (state.charts.detection) { 
        state.charts.detection.destroy(); 
        state.charts.detection = null; 
    }

    const ctx = canvas.getContext("2d");

    // Extract all module scores independently
    const moduleScores = extractModuleScores(result);
    
    // If any score is null, try to get a reasonable default (but don't use ML for all)
    const mlScore = moduleScores.ml ?? 50;
    const lexical = moduleScores.lexical ?? 50;
    const reputation = moduleScores.reputation ?? 50;
    const behavior = moduleScores.behavior ?? 50;
    const nlp = moduleScores.nlp ?? 50;

    console.log("📊 Detection chart data:", {
        ml: mlScore,
        lexical: lexical,
        reputation: reputation,
        behavior: behavior,
        nlp: nlp
    });

    state.charts.detection = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["ML Model ★", "Lexical", "Reputation", "Behavior", "NLP"],
            datasets: [{
                label: "Risk Score (%)",
                data:  [mlScore, lexical, reputation, behavior, nlp],
                backgroundColor: [
                    "rgba(139, 92, 246, 0.9)",   // ML — distinct colour + star label
                    "rgba(59, 130, 246, 0.8)",
                    "rgba(16, 185, 129, 0.8)",
                    "rgba(245, 158, 11, 0.8)",
                    "rgba(236, 72, 153, 0.8)"
                ],
                borderColor: [
                    "rgba(139, 92, 246, 1)",
                    "rgba(59, 130, 246, 1)",
                    "rgba(16, 185, 129, 1)",
                    "rgba(245, 158, 11, 1)",
                    "rgba(236, 72, 153, 1)"
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: "top",
                    labels: { color: "#e5e7eb", font: { size: 12, weight: "bold" } }
                },
                title: {
                    display: true,
                    text: "Multi-Module Detection Analysis  (★ = verdict driver)",
                    color: "#f9fafb",
                    font: { size: 15, weight: "bold" }
                },
                tooltip: {
                    backgroundColor: "rgba(17, 24, 39, 0.95)",
                    titleColor: "#f9fafb",
                    bodyColor:  "#e5e7eb",
                    borderColor: "#00ff41",
                    borderWidth: 1,
                    callbacks: {
                        label: (ctx) => {
                            const isML = ctx.dataIndex === 0;
                            return isML
                                ? `ML Confidence: ${ctx.parsed.y.toFixed(1)}%  ← verdict source`
                                : `${ctx.label}: ${ctx.parsed.y.toFixed(1)}%  (visualization only)`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: "#9ca3af", callback: v => v + "%" },
                    grid: { color: "rgba(75, 85, 99, 0.3)" }
                },
                x: {
                    ticks: { color: "#9ca3af", font: { size: 11 } },
                    grid: { display: false }
                }
            }
        }
    });
}

// ------------------------------------------------------------------
// ENSEMBLE CONTRIBUTION CHART - FIXED
// Shows weighted influence (contribution), NOT raw scores
// ------------------------------------------------------------------
function createEnsembleContributionChart(result) {
    const canvas = elements.ensembleChart;
    if (!canvas) return;

    if (state.charts.ensemble) { 
        state.charts.ensemble.destroy(); 
        state.charts.ensemble = null; 
    }

    const ctx = canvas.getContext("2d");

    // Check if backend provides ensemble_contributions
    let contributions = result.ensemble_contributions;
    
    if (!contributions) {
        // Calculate contributions manually from module scores and weights
        const moduleScores = extractModuleScores(result);
        
        // Convert to 0-1 range for calculation
        const toDecimal = (v) => (v != null ? v / 100 : 0);
        
        const rawContributions = {
            ml: (toDecimal(moduleScores.ml) || 0) * MODULE_WEIGHTS.ml,
            lexical: (toDecimal(moduleScores.lexical) || 0) * MODULE_WEIGHTS.lexical,
            reputation: (toDecimal(moduleScores.reputation) || 0) * MODULE_WEIGHTS.reputation,
            behavior: (toDecimal(moduleScores.behavior) || 0) * MODULE_WEIGHTS.behavior,
            nlp: (toDecimal(moduleScores.nlp) || 0) * MODULE_WEIGHTS.nlp
        };
        
        // Normalize to percentages
        const totalContribution = Object.values(rawContributions).reduce((a, b) => a + b, 0);
        
        if (totalContribution > 0) {
            contributions = {};
            for (const [key, value] of Object.entries(rawContributions)) {
                contributions[key] = (value / totalContribution) * 100;
            }
        } else {
            // Fallback to equal distribution if all scores are 0
            contributions = {
                ml: 20,
                lexical: 20,
                reputation: 20,
                behavior: 20,
                nlp: 20
            };
        }
    }

    console.log("🎯 Ensemble contributions:", contributions);

    const labels = [];
    const data = [];
    const colors = [
        "rgba(139, 92, 246, 0.85)",  // ML
        "rgba(59, 130, 246, 0.85)",   // Lexical
        "rgba(16, 185, 129, 0.85)",   // Reputation
        "rgba(245, 158, 11, 0.85)",   // Behavior
        "rgba(236, 72, 153, 0.85)"    // NLP
    ];

    const moduleNames = {
        ml: "ML Model",
        lexical: "Lexical",
        reputation: "Reputation",
        behavior: "Behavior",
        nlp: "NLP"
    };

    Object.entries(contributions).forEach(([key, value]) => {
        if (value != null && value > 0) {
            labels.push(moduleNames[key] || key);
            data.push(parseFloat(value.toFixed(2)));
        }
    });

    if (data.length === 0) {
        console.warn("No contribution data available for ensemble chart");
        return;
    }

    state.charts.ensemble = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                label: "Contribution %",
                data,
                backgroundColor: colors.slice(0, data.length),
                borderColor: "#1f2937",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "right",
                    labels: { color: "#e5e7eb", font: { size: 11 }, padding: 10 }
                },
                title: {
                    display: true,
                    text:    "Ensemble Module Contributions (Weighted Influence)",
                    color:   "#f9fafb",
                    font:    { size: 14, weight: "bold" }
                },
                tooltip: {
                    backgroundColor: "rgba(17, 24, 39, 0.95)",
                    titleColor: "#f9fafb",
                    bodyColor:  "#e5e7eb",
                    borderColor: "#00ff41",
                    borderWidth: 1,
                    callbacks: {
                        label: ctx => {
                            const note = ctx.label.includes("ML") ? " ← verdict source" : " (influences final score)";
                            return `${ctx.label}: ${ctx.parsed}%${note}`;
                        }
                    }
                }
            }
        }
    });
}

// ------------------------------------------------------------------
// HORIZONTAL FEATURES BAR CHART
// ------------------------------------------------------------------
function displayDetailedAnalysis(data, mlConfidencePct) {
    if (!elements.featuresChart) return;
    if (state.charts.features) { state.charts.features.destroy(); state.charts.features = null; }

    const metrics    = data.metrics  || {};
    const features   = metrics.features || {};
    const chartData  = [];

    chartData.push({ label: "ML Confidence", value: mlConfidencePct, color: "rgba(139, 0, 139, 0.7)" });

    if (features.url_length !== undefined) {
        const norm = Math.min((features.url_length / 100) * 100, 100);
        chartData.push({ label: "URL Length", value: norm, color: norm > 75 ? "rgba(255, 0, 110, 0.7)" : "rgba(0, 255, 65, 0.7)" });
    }
    if (features.has_https !== undefined) {
        chartData.push({ label: "HTTPS Security", value: features.has_https * 100, color: features.has_https ? "rgba(0, 255, 65, 0.7)" : "rgba(255, 0, 110, 0.7)" });
    }
    if (features.subdomain_count !== undefined) {
        const subScore = Math.min((features.subdomain_count / 5) * 100, 100);
        chartData.push({ label: "Subdomain Count", value: subScore, color: subScore > 60 ? "rgba(255, 190, 11, 0.7)" : "rgba(0, 255, 65, 0.7)" });
    }
    if (features.has_ip !== undefined) {
        chartData.push({ label: "IP in URL", value: features.has_ip * 100, color: features.has_ip ? "rgba(255, 0, 110, 0.7)" : "rgba(0, 255, 65, 0.7)" });
    }
    if (features.has_suspicious_keywords !== undefined) {
        chartData.push({ label: "Suspicious Keywords", value: features.has_suspicious_keywords * 100, color: features.has_suspicious_keywords ? "rgba(255, 190, 11, 0.7)" : "rgba(0, 255, 65, 0.7)" });
    }

    const ctx = elements.featuresChart.getContext("2d");
    state.charts.features = new Chart(ctx, {
        type: "bar",
        data: {
            labels:   chartData.map(d => d.label),
            datasets: [{
                label:           "Analysis Score (%)",
                data:            chartData.map(d => d.value),
                backgroundColor: chartData.map(d => d.color),
                borderColor:     chartData.map(d => d.color.replace("0.7", "1")),
                borderWidth:     2,
                borderRadius:    6
            }]
        },
        options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { beginAtZero: true, max: 100, ticks: { color: "#a0a0a0", callback: v => v + "%" }, grid: { color: "rgba(255,255,255,0.1)" } },
                y: { ticks: { color: "#e8e8e8", font: { size: 12 } }, grid: { display: false } }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(0,0,0,0.8)",
                    titleColor: "#00ff41",
                    bodyColor:  "#e8e8e8",
                    borderColor: "#00ff41",
                    borderWidth: 1,
                    padding: 12,
                    displayColors: false,
                    callbacks: { label: ctx => ctx.parsed.x.toFixed(1) + "%" }
                }
            }
        }
    });
}

// ------------------------------------------------------------------
// LOADING
// ------------------------------------------------------------------
const LOADING_STAGES = [
    "Connecting to server...",
    "Extracting URL features...",
    "Running ML analysis...",
    "Analyzing risk factors...",
    "Finalizing report..."
];

function showLoading() {
    elements.loading.classList.remove("hidden");
    elements.scanBtn.disabled = true;
    elements.scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    updateLoadingStage("Initializing scan...", 10);
}
function hideLoading() {
    elements.loading.classList.add("hidden");
    elements.scanBtn.disabled = false;
    elements.scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Website';
}
function updateLoadingStage(stage, progress) {
    if (elements.loadingStage) elements.loadingStage.textContent = stage;
    if (elements.progressBar)  elements.progressBar.style.width = `${progress}%`;
}
function simulateProgress() {
    let progress = 0, stageIndex = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 20;
        if (progress > 90) progress = 90;
        if (elements.progressBar) elements.progressBar.style.width = progress + "%";
        if (stageIndex < LOADING_STAGES.length) {
            updateLoadingStage(LOADING_STAGES[stageIndex], progress);
            stageIndex++;
        }
        if (elements.loadingTime) {
            const elapsed = ((Date.now() - state.scanStartTime) / 1000).toFixed(1);
            elements.loadingTime.textContent = elapsed + "s";
        }
    }, 300);
    setTimeout(() => { clearInterval(interval); if (elements.progressBar) elements.progressBar.style.width = "100%"; }, 2000);
}

// ------------------------------------------------------------------
// RESET UI
// ------------------------------------------------------------------
function resetResultUI() {
    elements.resultCard.classList.add("hidden");
    elements.resultCard.style.opacity   = "0";
    elements.resultCard.style.transform = "translateY(20px)";
    if (elements.progressBar) elements.progressBar.style.width = "0%";
    if (elements.urlPreview)  elements.urlPreview.classList.remove("show");
}

// ------------------------------------------------------------------
// STATS
// ------------------------------------------------------------------
function updateStats(data) {
    state.stats.totalScans++;
    const classification = data.classification || data.label || "";
    if (["Phishing","PHISHING","Suspicious","SUSPICIOUS"].includes(classification))
        state.stats.threatsBlocked++;
    state.stats.totalScanTime += (Date.now() - state.scanStartTime) / 1000;
    saveStats();
    updateStatsDisplay();
}
function updateStatsDisplay() {
    if (elements.totalScans)     elements.totalScans.textContent     = state.stats.totalScans;
    if (elements.threatsBlocked) elements.threatsBlocked.textContent = state.stats.threatsBlocked;
    if (elements.avgScanTime && state.stats.totalScans > 0) {
        const avg = (state.stats.totalScanTime / state.stats.totalScans).toFixed(1);
        elements.avgScanTime.textContent = avg + "s";
    }
}
function saveStats() { localStorage.setItem("phishguard_stats", JSON.stringify(state.stats)); }
function loadStats() {
    const saved = localStorage.getItem("phishguard_stats");
    if (saved) { try { state.stats = JSON.parse(saved); } catch {} }
}

// ------------------------------------------------------------------
// HISTORY
// ------------------------------------------------------------------
function saveToHistory(data, duration) {
    const mlScore = extractMLScore(data);
    const entry = {
        url:            data.url,
        classification: mlScore >= ML_PHISHING_THRESHOLD  ? "Phishing"
                      : mlScore >= ML_SUSPICIOUS_THRESHOLD ? "Suspicious"
                      : "Legitimate",
        confidence:     mlScore,
        timestamp:      data.timestamp || new Date().toISOString(),
        duration:       duration || 0
    };
    state.history.unshift(entry);
    if (state.history.length > CONFIG.MAX_HISTORY) state.history.pop();
    localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(state.history));
    updateHistoryDisplay();
}
function loadHistory() {
    const saved = localStorage.getItem(CONFIG.STORAGE_KEY);
    if (saved) { try { state.history = JSON.parse(saved); } catch { state.history = []; } }
    updateHistoryDisplay();
}
function updateHistoryDisplay() {
    if (!elements.historyList) return;
    elements.historyList.innerHTML = "";
    if (state.history.length === 0) {
        elements.historyList.innerHTML = '<div class="no-history">No scan history yet</div>';
        return;
    }
    state.history.forEach(entry => {
        const c = entry.classification || "Unknown";
        let sc = (c === "Phishing" || c === "PHISHING") ? "danger" : (c === "Suspicious" || c === "SUSPICIOUS") ? "warning" : "safe";
        const iconMap = { danger: "fa-exclamation-triangle", warning: "fa-exclamation-circle", safe: "fa-check-circle" };
        const div = document.createElement("div");
        div.className = "history-item";
        div.innerHTML = `
            <div class="history-header">
                <span class="history-status ${sc}"><i class="fas ${iconMap[sc]}"></i> ${c}</span>
                <span class="history-confidence">${entry.confidence}%</span>
            </div>
            <div class="history-url">${truncateUrl(entry.url, 40)}</div>
            <div class="history-meta">
                <span>${new Date(entry.timestamp).toLocaleString()}</span>
                <span>${entry.duration ? entry.duration + "ms" : ""}</span>
            </div>`;
        div.addEventListener("click", () => { elements.urlInput.value = entry.url; toggleHistory(); });
        elements.historyList.appendChild(div);
    });
}
function clearHistory() {
    if (confirm("Are you sure you want to clear all scan history?")) {
        state.history = [];
        localStorage.removeItem(CONFIG.STORAGE_KEY);
        updateHistoryDisplay();
        showToast("History cleared", "success");
    }
}
function toggleHistory() { elements.historySidebar?.classList.toggle("hidden"); }

// ------------------------------------------------------------------
// RESULT ACTIONS
// ------------------------------------------------------------------
function copyResult() {
    if (!state.currentScan) { showToast("No scan result to copy", "error"); return; }
    const text = `PhishGuard AI Scan Result\nURL:        ${state.currentScan.url}\nStatus:     ${state.currentScan.classification}\nConfidence: ${state.currentScan.confidence}% (ML only)\nRisk Level: ${state.currentScan.riskLevel}\nTimestamp:  ${new Date(state.currentScan.timestamp).toLocaleString()}`.trim();
    navigator.clipboard.writeText(text)
        .then(() => showToast("Result copied to clipboard", "success"))
        .catch(() => showToast("Failed to copy to clipboard", "error"));
}
function shareResult() {
    if (!state.currentScan) { showToast("No scan result to share", "error"); return; }
    if (typeof isAuthenticated === "function" && !isAuthenticated()) {
        if (typeof showAuthModal === "function") showAuthModal("share", shareResult);
        else showToast("Please log in to share results", "warning");
        return;
    }
    if (navigator.share) {
        navigator.share({ title: "PhishGuard AI Scan Result", text: `PhishGuard AI: ${state.currentScan.url} is ${state.currentScan.classification} (${state.currentScan.confidence}% ML confidence)`, url: window.location.href })
            .catch(() => showToast("Share cancelled", "info"));
    } else {
        showToast("Share not supported on this browser", "info");
    }
}
function exportResult() {
    if (!state.currentScan) { showToast("No scan result to export", "error"); return; }
    if (typeof isAuthenticated === "function" && !isAuthenticated()) {
        if (typeof showAuthModal === "function") showAuthModal("export", exportResult);
        else showToast("Please log in to export results", "warning");
        return;
    }
    const exportData = {
        ...state.currentScan,
        exportedAt: new Date().toISOString(),
        scoringPolicy: "final_classification based on ML score only"
    };
    const json  = JSON.stringify(exportData, null, 2);
    const blob  = new Blob([json], { type: "application/json" });
    const bUrl  = URL.createObjectURL(blob);
    const a     = document.createElement("a");
    a.href      = bUrl;
    a.download  = `phishguard-scan-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(bUrl);
    showToast("Report exported successfully", "success");
}

// ------------------------------------------------------------------
// DETAILS ACCORDION
// ------------------------------------------------------------------
function toggleDetails() {
    const content = elements.detailsContent;
    const icon    = elements.detailsToggle?.querySelector("i");
    if (!content) return;
    const isOpen = content.classList.contains("expanded");
    if (isOpen) {
        content.classList.remove("expanded");
        content.classList.add("hidden");
        if (icon) { icon.classList.remove("fa-chevron-up"); icon.classList.add("fa-chevron-down"); }
    } else {
        content.classList.remove("hidden");
        content.classList.add("expanded");
        if (icon) { icon.classList.remove("fa-chevron-down"); icon.classList.add("fa-chevron-up"); }
    }
}

// ------------------------------------------------------------------
// TOAST
// ------------------------------------------------------------------
function showToast(message, type = "info") {
    if (!elements.toast) return;
    elements.toast.textContent = message;
    elements.toast.className   = `toast ${type}`;
    elements.toast.classList.remove("hidden");
    setTimeout(() => elements.toast.classList.add("hidden"), 3000);
}

// ------------------------------------------------------------------
// UTILITIES
// ------------------------------------------------------------------
function isValidURL(url) { try { new URL(url); return true; } catch { return false; } }
function truncateUrl(url, maxLength = 50) { if (url.length <= maxLength) return url; return url.substring(0, maxLength - 3) + "..."; }

// ------------------------------------------------------------------
// BOOTSTRAP
// ------------------------------------------------------------------
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
} else {
    init();
}