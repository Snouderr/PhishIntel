// Shared by the background worker (importScripts), popup, options and warning pages.

const DEFAULT_SETTINGS = {
  apiUrl: 'http://localhost:8000',
  blockHighRisk: true,  // full-page warning for high-risk pages
  warnMedium: true,     // banner on medium-risk pages
  logChecks: false,     // store checks in the backend's local DB (off: it's browsing history)
  allowlist: [],        // hostnames the user chose to trust
};

async function getSettings() {
  return chrome.storage.sync.get(DEFAULT_SETTINGS);
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

// A trusted host also covers its subdomains (trusting example.com trusts www.example.com).
function isAllowlisted(host, allowlist) {
  return allowlist.some(h => host === h || host.endsWith('.' + h));
}
