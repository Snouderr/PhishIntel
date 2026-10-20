const tabId = Number(new URLSearchParams(location.search).get('tab'));
const note = document.getElementById('note');
let info = null;

function render() {
  if (!info) {
    document.getElementById('url').textContent = 'The page details are no longer available.';
    return;
  }
  // Highlight the real hostname — the part attackers try to disguise.
  const urlEl = document.getElementById('url');
  try {
    const u = new URL(info.url);
    const strong = document.createElement('strong');
    strong.textContent = u.hostname;
    urlEl.append(`${u.protocol}//`, strong, u.pathname + u.search);
  } catch {
    urlEl.textContent = info.url;
  }
  document.getElementById('score').textContent =
    `Phishing probability: ${Math.round(info.probability * 100)}%` + (info.reasons?.length ? ' — why:' : '');
  const list = document.getElementById('reasons');
  for (const r of info.reasons || []) {
    const li = document.createElement('li');
    li.textContent = r;
    list.append(li);
  }
}

chrome.runtime.sendMessage({ type: 'GET_WARNING', tabId }, res => {
  info = res;
  render();
});

document.getElementById('back').addEventListener('click', () => {
  // History is: previous page -> blocked page -> this warning.
  if (history.length > 2) history.go(-2);
  else chrome.tabs.update(tabId, { url: 'chrome://newtab' });
});

document.getElementById('proceed').addEventListener('click', () => {
  if (!info) return;
  if (!confirm('Open this page anyway? Never enter passwords or payment details on a page you were warned about.')) return;
  chrome.runtime.sendMessage({ type: 'PROCEED', tabId, url: info.url });
});

document.getElementById('report').addEventListener('click', () => {
  if (!info) return;
  chrome.runtime.sendMessage({ type: 'REPORT', url: info.url, label: 'false_positive', result: info }, res => {
    note.textContent = res?.ok
      ? 'Thanks — reported as a false alarm. Use "Proceed anyway" to open it, or trust the site from the extension popup.'
      : 'Could not send the report (is the backend running?).';
  });
});
