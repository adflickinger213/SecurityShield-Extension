// Security Shield - Content Script
document.addEventListener('click', (e) => {
    if (!(e.target instanceof Element)) {
          return;
    }
    const link = e.target.closest('a');
    if (link) {
          const href = link.getAttribute('href');
          if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
                  checkLink(href, link);
          }
    }
}, true);

function checkLink(url, element) {
    chrome.runtime.sendMessage({ type: 'checkLink', url: url }, (response) => {
          if (chrome.runtime.lastError || !response) {
                  return;
          }
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
    // This script runs at document_start, when document.body is still null;
    // observing the document node covers the whole tree once it is parsed.
    observer.observe(document, { childList: true, subtree: true });
}

// DOM-clobbering safe: a page can shadow form.action with
// <input name="action">, which would make the property return an element
// instead of the URL and let an insecure form evade the check.
function getFormAction(form) {
    const action = form.getAttribute('action');
    if (typeof action !== 'string' || action === '') {
          return window.location.href;
    }
    try {
          return new URL(action, window.location.href).href;
    } catch (e) {
          return null;
    }
}

document.addEventListener('submit', (e) => {
    if (!(e.target instanceof HTMLFormElement)) {
          return;
    }
    const action = getFormAction(e.target);
    if (action && action.startsWith('http://')) {
          console.warn('⚠️ WARNING: Form submitting to HTTP (unencrypted) URL');
    }
}, true);
