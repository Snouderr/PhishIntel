// Background service worker (Manifest V3).
// Checks every top-level navigation with the backend's /predict, then:
//   high risk   -> full-page warning (warning.html), unless the user chose to proceed
//   medium risk -> dismissible banner on the page (content.js)
// and keeps the toolbar badge + popup in sync.

importScripts('settings.js');

const cache = new Map(); // url -> result
const CACHE_TTL_MS = 5 * 60 * 1000;

function isCheckable(url, settings) {
  if (!url || !/^https?:/i.test(url)) return false;
  // Don't score the detector's own API / PhishIntel pages
  try { return new URL(url).origin !== new URL(settings.apiUrl).origin; } catch { return true; }
}

async function checkUrl(url, settings) {
  const host = hostOf(url);
  if (isAllowlisted(host, settings.allowlist)) {
    return { riskLevel: 'safe', probability: 0, reasons: [], allowlisted: true, ts: Date.now() };
  }
  const cached = cache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached;

  try {
    const res = await fetch(`${settings.apiUrl}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, log: settings.logChecks, source: 'extension' }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    const data = await res.json();
    const result = {
      isPhishing: data.is_phishing,
      probability: data.phishing_probability,
      riskLevel: data.risk_level,
      trustOverrideApplied: data.trust_override_applied || false,
      reasons: (data.reasons || []).map(r => r.reason),
      modelVersion: data.model_version,
      ts: Date.now(),
    };
    cache.set(url, result);
    return result;
  } catch (err) {
    console.warn('Phishing Detector: API call failed', err);
    return null; // fail open — never block browsing because the API is down
  }
}

async function bypassed(host) {
  const { bypass = [] } = await chrome.storage.session.get('bypass');
  return bypass.includes(host);
}

function setBadge(tabId, risk) {
  const text = { high: '!!', medium: '!' }[risk] || '';
  const color = { high: '#d32f2f', medium: '#f57c00', low: '#fbc02d', safe: '#388e3c' }[risk] || '#888';
  chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {});
}

// stage: 'committed' (early — may block), 'completed' / 'history' (page ready — banner)
async function evaluate(tabId, url, stage) {
  const settings = await getSettings();
  if (!isCheckable(url, settings)) return;
  const result = await checkUrl(url, settings);
  if (!result) return;

  await chrome.storage.session.set({ [`result_${tabId}`]: { url, ...result } });
  setBadge(tabId, result.riskLevel);

  const host = hostOf(url);
  if (result.riskLevel === 'high' && settings.blockHighRisk && !(await bypassed(host))) {
    await chrome.storage.session.set({ [`warning_${tabId}`]: { url, ...result } });
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning.html?tab=${tabId}`) });
    return;
  }
  if (stage === 'committed') return; // content script isn't ready yet; banner follows on 'completed'

  const showBanner = result.riskLevel === 'high' || (result.riskLevel === 'medium' && settings.warnMedium);
  // Always send CLEAR otherwise: on single-page apps a banner from the
  // previous URL would stay forever, since the page never reloads.
  chrome.tabs.sendMessage(tabId, showBanner ? { type: 'PHISHING_WARNING', ...result } : { type: 'PHISHING_CLEAR' })
    .catch(() => {});
}

chrome.webNavigation.onCommitted.addListener(d => {
  if (d.frameId === 0) evaluate(d.tabId, d.url, 'committed');
});
chrome.webNavigation.onCompleted.addListener(d => {
  if (d.frameId === 0) evaluate(d.tabId, d.url, 'completed');
});
// Client-side route changes (pushState) on single-page apps
chrome.webNavigation.onHistoryStateUpdated.addListener(d => {
  if (d.frameId === 0) evaluate(d.tabId, d.url, 'history');
});

async function sendFeedback(url, label, result) {
  const settings = await getSettings();
  const res = await fetch(`${settings.apiUrl}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url, label, source: 'extension',
      risk_level: result?.riskLevel, probability: result?.probability, model_version: result?.modelVersion,
    }),
  });
  if (!res.ok) throw new Error(`API returned ${res.status}`);
}

async function trustSite(host) {
  const settings = await getSettings();
  if (!settings.allowlist.includes(host)) {
    await chrome.storage.sync.set({ allowlist: [...settings.allowlist, host] });
  }
  for (const key of cache.keys()) if (isAllowlisted(hostOf(key), [host])) cache.delete(key);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case 'CHECK_ACTIVE_TAB': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return sendResponse(null);
        const settings = await getSettings();
        if (!isCheckable(tab.url, settings)) return sendResponse({ url: tab.url, notApplicable: true });
        if (msg.fresh) cache.delete(tab.url);
        const result = await checkUrl(tab.url, settings);
        return sendResponse(result ? { url: tab.url, ...result } : null);
      }
      case 'REPORT':
        await sendFeedback(msg.url, msg.label, msg.result);
        return sendResponse({ ok: true });
      case 'TRUST_SITE':
        await trustSite(msg.host);
        if (msg.tabId) chrome.tabs.sendMessage(msg.tabId, { type: 'PHISHING_CLEAR' }).catch(() => {});
        return sendResponse({ ok: true });
      case 'GET_WARNING': {
        const key = `warning_${msg.tabId}`;
        const data = await chrome.storage.session.get(key);
        return sendResponse(data[key] || null);
      }
      case 'PROCEED': {
        // "Proceed anyway": skip the full-page warning for this host until the
        // browser restarts (session storage), but keep the banner.
        const { bypass = [] } = await chrome.storage.session.get('bypass');
        const host = hostOf(msg.url);
        if (!bypass.includes(host)) await chrome.storage.session.set({ bypass: [...bypass, host] });
        await chrome.tabs.update(msg.tabId, { url: msg.url });
        return sendResponse({ ok: true });
      }
      default:
        return sendResponse(null);
    }
  })().catch(err => sendResponse({ error: String(err.message || err) }));
  return true; // async response
});

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove([`result_${tabId}`, `warning_${tabId}`]).catch(() => {});
});
