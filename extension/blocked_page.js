// blocked_page.js
// Reads detection data from chrome.storage.local, populates UI, wires buttons

document.addEventListener('DOMContentLoaded', async () => {

  const blockedUrlEl     = document.getElementById('blocked-url');
  const riskLevelEl      = document.getElementById('risk-level');
  const confidenceEl     = document.getElementById('confidence');
  const classificationEl = document.getElementById('classification');
  const timestampEl      = document.getElementById('timestamp');
  const goBackBtn        = document.getElementById('go-back');
  const proceedBtn       = document.getElementById('proceed');

  let originalUrl = null;

  // ── Load detection data from storage ────────────────────────────────────
  try {
    const data = await chrome.storage.local.get('lastDetection');
    const d = data.lastDetection;

    if (d) {
      originalUrl = d.originalUrl || d.url || null;

      // Blocked URL
      if (blockedUrlEl) {
        blockedUrlEl.textContent = originalUrl || 'Unknown URL';
        blockedUrlEl.title       = originalUrl || '';
      }

      // Risk level
      if (riskLevelEl && d.risk_level) {
        riskLevelEl.textContent = d.risk_level.toUpperCase();
      }

      // Confidence
      if (confidenceEl && d.confidence !== undefined && d.confidence !== null) {
        confidenceEl.textContent = Number(d.confidence).toFixed(2) + '%';
      }

      // Classification
      if (classificationEl && d.classification) {
        classificationEl.textContent = d.classification;
      }

      // Timestamp
      if (timestampEl && d.timestamp) {
        const date = new Date(d.timestamp);
        timestampEl.textContent = date.toLocaleTimeString([], {
          hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
      }

    } else {
      if (blockedUrlEl) blockedUrlEl.textContent = 'URL unavailable';
    }

  } catch (err) {
    console.error('PhishGuard: failed to load detection data', err);
    if (blockedUrlEl) blockedUrlEl.textContent = 'Error loading URL';
  }

  // ── Button: Go Back to Safety ────────────────────────────────────────────
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    });
  }

  // ── Button: Ignore Warning / Proceed Anyway ──────────────────────────────
  if (proceedBtn) {
    proceedBtn.addEventListener('click', async () => {
      if (!originalUrl) {
        alert('Original URL is unavailable. Cannot proceed.');
        return;
      }

      const confirmed = window.confirm(
        '⚠️ DANGER: This site was flagged as PHISHING.\n\n' +
        'Proceeding may expose you to:\n' +
        '  • Password / credential theft\n' +
        '  • Financial fraud\n' +
        '  • Malware installation\n\n' +
        'Are you absolutely sure you want to continue?'
      );

      if (confirmed) {
        try {
          // Remove lastDetection so nav guard does not re-block immediately
          await chrome.storage.local.remove('lastDetection');
        } catch (_) { /* ignore */ }

        window.location.href = originalUrl;
      }
    });
  }

});