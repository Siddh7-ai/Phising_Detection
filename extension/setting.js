const autoScan = document.getElementById("autoScan");
const sensitivity = document.getElementById("sensitivity");

chrome.storage.sync.get(["autoScan", "sensitivity"], data => {
  autoScan.checked = data.autoScan ?? true;
  sensitivity.value = data.sensitivity ?? "Medium";
});

autoScan.onchange = save;
sensitivity.onchange = save;

function save() {
  chrome.storage.sync.set({
    autoScan: autoScan.checked,
    sensitivity: sensitivity.value
  });
}
