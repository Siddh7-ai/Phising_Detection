// === frontend/script.js ===

// DOM Elements
const scanBtn = document.getElementById("scanBtn");
const urlInput = document.getElementById("urlInput");
const loadingDiv = document.getElementById("loading");
const resultCard = document.getElementById("resultCard");
const statusDiv = document.getElementById("status");
const confidenceValue = document.getElementById("confidenceValue");
const riskLevelSpan = document.getElementById("riskLevel");
const riskFactorsList = document.getElementById("riskFactors");

// Backend API URL
const API_URL = "http://127.0.0.1:5000/check_url";

// Utility: Reset UI
function resetUI() {
    resultCard.classList.add("hidden");
    riskFactorsList.innerHTML = "";
}

// Utility: Validate URL format (basic)
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Update Result UI based on API response
function updateResult(data) {
    // Show result card
    resultCard.classList.remove("hidden");

    // Status styling
    statusDiv.className = "status"; // reset classes
    statusDiv.textContent = data.label;

    if (data.label === "SAFE") {
        statusDiv.classList.add("safe");
    } else if (data.label === "SUSPICIOUS") {
        statusDiv.classList.add("suspicious");
    } else {
        statusDiv.classList.add("phishing");
    }

    // Confidence & risk
    confidenceValue.textContent = `${Math.round(data.confidence * 100)}%`;
    riskLevelSpan.textContent = data.risk_level;

    // Risk factors
    if (data.risk_factors.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No significant phishing indicators detected.";
        riskFactorsList.appendChild(li);
    } else {
        data.risk_factors.forEach(factor => {
            const li = document.createElement("li");
            li.textContent = factor;
            riskFactorsList.appendChild(li);
        });
    }
}

// Handle Scan Button Click
scanBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    resetUI();

    // Input validation
    if (!url) {
        alert("Please enter a website URL.");
        return;
    }

    if (!isValidURL(url)) {
        alert("Invalid URL format. Please include http:// or https://");
        return;
    }

    // Show loading animation
    loadingDiv.classList.remove("hidden");

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error("Server error while scanning URL");
        }

        const data = await response.json();
        updateResult(data);

    } catch (error) {
        alert("Error: Unable to scan the website. Please check backend server.");
        console.error(error);
    } finally {
        // Hide loading animation
        loadingDiv.classList.add("hidden");
    }
});

// UX Enhancement: Scan on Enter key
urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        scanBtn.click();
    }
});
