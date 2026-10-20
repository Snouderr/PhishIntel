// Injected into every page. Shows / clears a dismissible warning banner when
// the background worker reports a risky page. Built with DOM APIs inside a
// shadow root, so the page's CSS can't restyle or hide it and nothing from
// the result is ever parsed as HTML.

const HOST_ID = '__phishing_detector_banner';

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'PHISHING_WARNING') showWarningBanner(msg);
  else if (msg.type === 'PHISHING_CLEAR') clearWarningBanner();
});

function clearWarningBanner() {
  document.getElementById(HOST_ID)?.remove();
}

function showWarningBanner({ riskLevel, probability, reasons = [] }) {
  clearWarningBanner();
  const pct = Math.round(probability * 100);
  const color = riskLevel === 'high' ? '#c62828' : '#e65100';

  const host = document.createElement('div');
  host.id = HOST_ID;
  host.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;';
  const root = host.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    .bar { background:${color}; color:#fff; font:14px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif;
           padding:10px 16px; display:flex; align-items:center; gap:12px;
           box-shadow:0 2px 6px rgba(0,0,0,.3); }
    .msg { flex:1; }
    .why { font-size:12px; opacity:.9; margin-top:2px; }
    button { background:rgba(255,255,255,.2); border:none; color:#fff; padding:5px 12px;
             border-radius:4px; cursor:pointer; font:inherit; font-size:13px; }
    button:hover { background:rgba(255,255,255,.3); }`;

  const bar = document.createElement('div');
  bar.className = 'bar';
  const msg = document.createElement('div');
  msg.className = 'msg';
  const title = document.createElement('div');
  title.textContent = riskLevel === 'high'
    ? `⚠️ This page is very likely phishing (${pct}%). Don't enter passwords or payment details.`
    : `⚠️ This page looks suspicious (${pct}% phishing). Be careful entering any information.`;
  msg.append(title);
  if (reasons.length) {
    const why = document.createElement('div');
    why.className = 'why';
    why.textContent = 'Why: ' + reasons.slice(0, 2).join(' · ');
    msg.append(why);
  }
  const dismiss = document.createElement('button');
  dismiss.textContent = 'Dismiss';
  dismiss.addEventListener('click', () => host.remove());

  bar.append(msg, dismiss);
  root.append(style, bar);
  document.documentElement.prepend(host);
}
