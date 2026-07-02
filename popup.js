// Security Shield - Popup Script

document.addEventListener('DOMContentLoaded', () => {
    loadSecurityStatus();
    // MV3 CSP blocks inline onclick handlers, so buttons are wired up here.
    document.getElementById('view-log').addEventListener('click', viewLog);
    document.getElementById('clear-log').addEventListener('click', clearLog);
});

function loadSecurityStatus() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const tab = tabs && tabs[0];
          const statusText = document.getElementById('status');
          if (!statusText) {
                  return;
          }
          let url = null;
          if (tab && typeof tab.url === 'string') {
                  try {
                            url = new URL(tab.url);
                  } catch (e) {
                            url = null;
                  }
          }
          if (!url) {
                  statusText.textContent = 'Status unavailable';
          } else if (url.protocol === 'https:') {
                  statusText.textContent = 'Secure HTTPS connection';
          } else if (url.protocol === 'http:') {
                  statusText.textContent = 'WARNING: Unencrypted HTTP connection';
          } else {
                  statusText.textContent = 'Not a web page';
          }
    });
}

function viewLog() {
    chrome.storage.local.get('securityLog', (result) => {
          const log = Array.isArray(result.securityLog) ? result.securityLog : [];
          alert(`Security Log: ${log.length} events recorded`);
    });
}

function clearLog() {
    if (confirm('Clear all security logs?')) {
          chrome.storage.local.set({ securityLog: [] });
          alert('Security log cleared');
    }
}
