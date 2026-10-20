const statusEl = document.getElementById('status');
const urlBoxEl = document.getElementById('url-box');
const urlDomainEl = document.getElementById('url-domain');
const urlPathEl = document.getElementById('url-path');
const reasonsEl = document.getElementById('reasons');
const actionsEl = document.getElementById('actions');
const noteEl = document.getElementById('feedback-note');
const btn = id => document.getElementById(id);

const LABELS = {
  safe: '✅ Looks safe',
  low: '🟡 Low risk',
  medium: '🟠 Medium risk — be careful',
  high: '🔴 High risk — likely phishing',
};
const BAR_COLORS = { safe: '#2e7d32', low: '#c9a100', medium: '#e07b00', high: '#d32f2f' };

let current = null; // last result for the active tab
let activeTabId = null;

function splitUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const rest = u.pathname + u.search;
    return { domain: u.hostname, rest: rest === '/' ? '' : rest };
  } catch {
    return { domain: rawUrl, rest: '' };
  }
}

// Status box built with DOM APIs — nothing from the API is parsed as HTML.
function setStatus(className, verdict, label, pct, color) {
  statusEl.className = className;
  statusEl.replaceChildren();
  const v = document.createElement('div');
  v.className = 'verdict';
  v.textContent = verdict;
  statusEl.append(v);
  if (pct != null) {
    const track = document.createElement('div');
    track.id = 'bar-track';
    const fill = document.createElement('div');
    fill.id = 'bar-fill';
    fill.style.width = `${pct}%`;
    fill.style.background = color;
    track.append(fill);
    statusEl.append(track);
  }
  if (label) {
    const l = document.createElement('div');
    l.id = 'bar-label';
    l.style.color = color;
    l.textContent = label;
    statusEl.append(l);
  }
}

function render(result) {
  current = result;
  reasonsEl.style.display = 'none';
  actionsEl.style.display = 'none';
  noteEl.textContent = '';

  if (result?.notApplicable) {
    setStatus('loading', 'Not applicable — browser or PhishIntel page');
    urlDomainEl.textContent = result.url || '';
    urlPathEl.style.display = 'none';
    urlBoxEl.style.display = 'block';
    return;
  }
  if (!result || result.error) {
    setStatus('loading', 'Could not reach the detection API', 'Start the backend, or check the API address in Settings', null, '#666');
    urlBoxEl.style.display = 'none';
    return;
  }

  const risk = result.riskLevel || 'safe';
  const pct = Math.round((result.probability ?? 0) * 100);
  const color = BAR_COLORS[risk] || '#888';
  if (result.allowlisted) {
    setStatus(risk, LABELS.safe, 'On your trusted-sites list', null, color);
  } else if (result.trustOverrideApplied) {
    // Score capped by the reputation rule — a percentage would be misleading
    setStatus(risk, LABELS[risk], 'Trusted domain (reputation list)', null, color);
  } else {
    setStatus(risk, LABELS[risk] || 'Unknown', `${pct}% phishing probability`, pct, color);
  }

  const { domain, rest } = splitUrl(result.url || '');
  urlDomainEl.textContent = domain;
  urlDomainEl.title = result.url || '';
  urlPathEl.textContent = rest;
  urlPathEl.title = result.url || '';
  urlPathEl.style.display = rest ? 'block' : 'none';
  urlBoxEl.style.display = 'block';

  reasonsEl.replaceChildren(...(result.reasons || []).map(r => {
    const li = document.createElement('li');
    li.textContent = r;
    return li;
  }));
  reasonsEl.style.display = result.reasons?.length ? 'block' : 'none';

  const flagged = risk === 'medium' || risk === 'high';
  btn('report-fp').style.display = flagged ? 'block' : 'none';
  btn('trust').style.display = flagged && !result.allowlisted ? 'block' : 'none';
  btn('report-fn').style.display = flagged ? 'none' : 'block';
  actionsEl.style.display = 'flex';
  document.getElementById('version').textContent = result.modelVersion ? `model v${result.modelVersion}` : '';
}

function check(fresh = false) {
  setStatus('loading', 'Checking current page...');
  urlBoxEl.style.display = 'none';
  chrome.runtime.sendMessage({ type: 'CHECK_ACTIVE_TAB', fresh }, render);
}

function report(label, thanks) {
  if (!current?.url) return;
  chrome.runtime.sendMessage({ type: 'REPORT', url: current.url, label, result: current }, res => {
    noteEl.style.color = res?.ok ? '#2e7d32' : '#c62828';
    noteEl.textContent = res?.ok ? thanks : 'Could not send the report — is the backend running?';
  });
}

btn('recheck').addEventListener('click', () => check(true));
btn('report-fp').addEventListener('click', () => report('false_positive', 'Thanks — reported as a false alarm.'));
btn('report-fn').addEventListener('click', () => report('false_negative', 'Thanks — reported as phishing.'));
btn('trust').addEventListener('click', () => {
  const host = hostOf(current?.url || '');
  if (!host || !confirm(`Always trust ${host} (and its subdomains)? You can undo this in Settings.`)) return;
  chrome.runtime.sendMessage({ type: 'TRUST_SITE', host, tabId: activeTabId }, () => check(true));
});
btn('investigate').addEventListener('click', async () => {
  const { apiUrl } = await getSettings();
  chrome.tabs.create({ url: `${apiUrl}/app/#url=${encodeURIComponent(current.url)}` });
});
btn('open-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  activeTabId = tabs[0]?.id ?? null;
  check();
});
