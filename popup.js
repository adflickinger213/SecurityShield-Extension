// Security Shield - Popup Script

document.addEventListener('DOMContentLoaded', () => {
    loadSecurityStatus();
});

function loadSecurityStatus() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const tab = tabs[0];
          const url = new URL(tab.url);
          const isSecure = url.protocol === 'https:';
          const statusText = document.getElementById('status') || document.querySelector('.status-value');
          if (statusText) {
                  if (isSecure) {
                            statusText.textContent = 'Secure HTTPS connection';
                  } else {
                            statusText.textContent = 'WARNING: Unencrypted HTTP connection';
                  }
          }
    });
}

window.viewLog = function() {
    chrome.storage.local.get('securityLog', (result) => {
          const log = result.securityLog || [];
          alert(`Security Log: ${log.length} events recorded`);
    });
};

window.clearLog = function() {
    if (confirm('Clear all security logs?')) {
          chrome.storage.local.set({ securityLog: [] });
          alert('Security log cleared');
    }
};
