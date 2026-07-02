// Security Shield - Background Service Worker
const THREAT_PATTERNS = [
    /p[a0]ssw[o0]rd.*verify/i,
    /confirm.*[a0]cc[o0]unt/i,
    /update.*payment/i,
    /click.*immediately/i
  ];

// Hostnames that look like well-known brands but use character substitutions.
const LOOKALIKE_PATTERN = /[a0]m[a0]z[o0]n|[a0]pp[a0]l|[a4]ppl[e3]/i;
// The genuine domains the lookalike pattern would otherwise also match.
const LEGITIMATE_DOMAINS = ['amazon.com', 'apple.com'];

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
    if (!tab || typeof tab.url !== 'string') {
          return;
    }
    let url;
    try {
          url = new URL(tab.url);
    } catch (e) {
          return;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          return;
    }
    const issues = [];
    if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
          issues.push({ type: 'http', severity: 'high', message: 'Unencrypted HTTP connection', icon: '⚠️' });
    }
    if (typeof tab.title === 'string' && THREAT_PATTERNS.some(p => p.test(tab.title))) {
          issues.push({ type: 'phishing', severity: 'high', message: 'Possible phishing page', icon: '⛔' });
    }
    if (issues.length > 0) {
          // Log only origin + path: query strings and fragments can carry
          // session tokens or personal data that must not persist in storage.
          const sanitizedUrl = url.origin + url.pathname;
          chrome.storage.local.get('securityLog', (result) => {
                  const log = Array.isArray(result.securityLog) ? result.securityLog : [];
                  log.push({ timestamp: new Date().toISOString(), url: sanitizedUrl, issues: issues });
                  chrome.storage.local.set({ securityLog: log.slice(-50) });
          });
          chrome.action.setBadgeText({ text: '⚠', tabId });
          chrome.action.setBadgeBackgroundColor({ color: '#ff4444', tabId });
    }
}

function isLegitimateDomain(hostname) {
    return LEGITIMATE_DOMAINS.some(
          (domain) => hostname === domain || hostname.endsWith('.' + domain)
    );
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) {
          return;
    }
    if (!request || request.type !== 'checkLink' || typeof request.url !== 'string') {
          return;
    }
    let hostname;
    try {
          hostname = new URL(request.url).hostname.toLowerCase();
    } catch (e) {
          sendResponse({ safe: false });
          return;
    }
    // Only the hostname matters for lookalike detection; matching the full URL
    // would flag harmless links like example.com/?q=amazon. The genuine
    // domains are exempted so real amazon.com/apple.com links aren't flagged.
    const isSafe = isLegitimateDomain(hostname) || !LOOKALIKE_PATTERN.test(hostname);
    sendResponse({ safe: isSafe });
});
