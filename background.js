// Security Shield - Background Service Worker
const THREAT_PATTERNS = [
    /p[a0]ssw[o0]rd.*verify/i,
    /confirm.*[a0]cc[o0]unt/i,
    /update.*payment/i,
    /click.*immediately/i
  ];

chrome.storage.local.get('securityLog', (result) => {
    if (!result.securityLog) {
          chrome.storage.local.set({ securityLog: [] });
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
          analyzeTab(tabId, tab);
    }
});

function analyzeTab(tabId, tab) {
    const url = new URL(tab.url);
    const issues = [];
    if (url.protocol !== 'https:' && url.hostname !== 'localhost') {
          issues.push({ type: 'http', severity: 'high', message: 'Unencrypted HTTP connection', icon: '⚠️' });
    }
    if (THREAT_PATTERNS.some(p => p.test(tab.title))) {
          issues.push({ type: 'phishing', severity: 'high', message: 'Possible phishing page', icon: '⛔' });
    }
    if (issues.length > 0) {
          chrome.storage.local.get('securityLog', (result) => {
                  const log = result.securityLog || [];
                  log.push({ timestamp: new Date().toISOString(), url: tab.url, issues: issues });
                  chrome.storage.local.set({ securityLog: log.slice(-50) });
          });
          chrome.action.setBadgeText({ text: '⚠', tabId });
          chrome.action.setBadgeBackgroundColor({ color: '#ff4444', tabId });
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkLink') {
          const isSafe = !(/[a0]m[a0]zon|[a0]pp[a0]l/.test(request.url));
          sendResponse({ safe: isSafe });
    }
});
