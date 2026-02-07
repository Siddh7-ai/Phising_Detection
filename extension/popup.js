const urlText = document.getElementById("url");
const statusText = document.getElementById("status");
const reasonText = document.getElementById("reason");
const detailsBox = document.querySelector("details");

const API_URL = "http://127.0.0.1:5000/predict";
const TIMEOUT_MS = 5000;

document.body.style.fontFamily = "Arial, sans-serif";

// Safe fetch with timeout
function fetchWithTimeout(resource, options = {}) {
  return Promise.race([
    fetch(resource, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), TIMEOUT_MS)
    )
  ]);
}

chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const tab = tabs[0];

  if (!tab || !tab.url) {
    statusText.textContent = "Cannot access this page";
    detailsBox.style.display = "none";
    return;
  }

  const currentUrl = tab.url;
  let siteHost;

  try {
    siteHost = new URL(currentUrl).hostname;
  } catch {
    statusText.textContent = "Invalid URL";
    detailsBox.style.display = "none";
    return;
  }

  urlText.textContent = siteHost;

  // 🚨 Chrome Safe Browsing / blocked phishing pages
  if (
    document.title.includes("Dangerous") ||
    currentUrl.includes("verify-account") ||
    currentUrl.includes("secure-login")
  ) {
    statusText.textContent = "Phishing Detected";
    reasonText.textContent =
      "This website is blocked by Chrome Safe Browsing and shows strong phishing indicators.";
    detailsBox.style.display = "block";
    return;
  }

  // ✅ TRUSTED DOMAINS (NO ML SCAN)
  const trustedDomains = [
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "chrome.google.com",

    // Telegram
    "telegram.org",
    "web.telegram.org",
    "desktop.telegram.org"
  ];

  if (
    currentUrl.startsWith("chrome://") ||
    trustedDomains.some(domain => siteHost === domain)
  ) {
    statusText.textContent = "Trusted Website";
    reasonText.textContent =
      "This is a well-known and verified official website.";
    detailsBox.style.display = "none";
    return;
  }

  // 🔍 ML ANALYSIS FOR UNKNOWN WEBSITES
  try {
    statusText.textContent = "Scanning website...";

    const response = await fetchWithTimeout(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await response.json();

    if (data.prediction === "phishing") {
      statusText.textContent = "Phishing Detected";
      reasonText.textContent =
        data.reason || "Suspicious patterns detected.";
      detailsBox.style.display = "block";
    } else {
      statusText.textContent = "Safe Website";
      detailsBox.style.display = "none";
    }
  } catch (error) {
    console.error(error);
    statusText.textContent = "Analysis Failed";
    reasonText.textContent =
      "The website blocks automated analysis or the backend is unreachable.";
    detailsBox.style.display = "block";
  }
});
