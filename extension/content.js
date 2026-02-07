let blocked = false;

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SCAN_RESULT" && msg.data.prediction === "phishing") {
    blockPage(msg.data);
  }
});

function blockPage(data) {
  if (blocked) return;
  blocked = true;

  document.documentElement.innerHTML = `
    <div style="
      position:fixed;inset:0;
      background:#0f172a;
      color:white;
      font-family:sans-serif;
      display:flex;
      align-items:center;
      justify-content:center;
      z-index:999999">
      <div style="max-width:500px;text-align:center">
        <h1>⚠️ Phishing Alert</h1>
        <p>This site is highly dangerous.</p>
        <p><strong>Confidence:</strong> ${Math.round(data.confidence * 100)}%</p>
        <button onclick="history.back()" style="margin:10px">🔙 Go Back</button>
        <button onclick="location.reload()" style="margin:10px">⚠️ Proceed Anyway</button>
      </div>
    </div>
  `;
}
