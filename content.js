// Security Shield - Content Script
document.addEventListener('click', (e) => {
    if (e.target.tagName === 'A' || e.target.closest('a')) {
          const link = e.target.tagName === 'A' ? e.target : e.target.closest('a');
          const href = link.getAttribute('href');
          if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
                  checkLink(href, link);
          }
    }
}, true);

function checkLink(url, element) {
    chrome.runtime.sendMessage({ type: 'checkLink', url: url }, (response) => {
          if (!response.safe) {
                  element.style.borderBottom = '3px dashed #ff4444';
                  element.title = '⚠️ This link may be suspicious. Verify the domain before clicking.';
          }
    });
}

if (window.location.protocol === 'https:') {
    const observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
                  if (mutation.addedNodes.length > 0) {
                            mutation.addedNodes.forEach((node) => {
                                        if (node.nodeType === 1) {
                                                      const insecureResources = node.querySelectorAll('img[src^="http://"], script[src^="http://"], link[href^="http://"]');
                                                      if (insecureResources.length > 0) {
                                                                      console.warn('⚠️ Mixed content detected: Insecure resources on HTTPS page');
                                                      }
                                        }
                            });
                  }
          });
    });
    observer.observe(document.body, { childList: true, subtree: true });
}

document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.action && form.action.startsWith('http://')) {
          console.warn('⚠️ WARNING: Form submitting to HTTP (unencrypted) URL');
    }
}, true);
