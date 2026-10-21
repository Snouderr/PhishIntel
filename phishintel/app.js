// ─── CONFIG ──────────────────────────────────────────────
// Served by the FastAPI backend at /app → same origin. If index.html is
// opened straight from disk, fall back to the default local API address.
const API_BASE = location.protocol === 'file:' ? 'http://localhost:8000' : '';
const STORAGE_KEY = 'phishintel.case.v1';

const STAGES = ['Sample', 'Headers', 'URLs', 'IOCs', 'Infra', 'Report'];

const SAMPLES = [
  { file: 'docusign.eml', label: 'DocuSign lure' },
  { file: 'microsoft365.eml', label: 'Microsoft 365 credential phish' },
  { file: 'bank-kyc.eml', label: 'Bank KYC + attachment' },
  { file: 'quishing.eml', label: 'QR-code phishing (quishing)' },
  { file: 'voicemail.eml', label: 'Voicemail HTML attachment' },
  { file: 'legit-newsletter.eml', label: 'Legitimate email' },
];

// ─── STATE ───────────────────────────────────────────────
// One source of truth, persisted to localStorage so a refresh keeps the case.
function newCase() {
  const d = new Date();
  const ymd = d.toISOString().slice(0, 10).replace(/-/g, '');
  return {
    caseId: `CASE-${ymd}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    createdAt: d.toISOString(),
    stage: 0,
    emailRaw: '',
    sourceName: '',
    analysis: null,     // response from POST /analyze/email
    urlScores: {},      // url -> ML result from /enrich/url, or { error }
    urlIntel: {},       // url -> { blocklists, urlhaus, virustotal }
    enrichment: { domains: {}, ips: {} }, // /enrich/domain and /enrich/ip results
    customUrls: [],     // analyst-added URLs
    manualIocs: [],     // analyst-added IOCs
    removedIocs: [],    // keys of auto IOCs the analyst dismissed
    defang: true,       // defang indicators in exports
    ai: {},             // panel id -> { text, provider, model } | { loading } | { error }
    aiProvider: 'template', // template | ollama | gemini
    aiRedact: true,     // redact recipient data before sending to an LLM
    aiPreview: null,    // { target, kind, prompt } awaiting confirmation (cloud only)
  };
}

let state = loadState();
let busy = false;
let config = null; // GET /config — which AI providers / intel sources are available

function loadState() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (saved && saved.caseId) return { ...newCase(), ...saved };
  } catch { /* storage unavailable or corrupt — start fresh */ }
  return newCase();
}

function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch { /* ignore */ }
}

// ─── HELPERS ─────────────────────────────────────────────
// Every value that came from the email or the analyst goes through esc()
// before it touches innerHTML.
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function defang(type, value) {
  const v = String(value);
  if (type === 'Hash') return v;
  if (type === 'URL') {
    return v.replace(/^http/i, 'hxxp').replace(/^(hxxps?:\/\/)([^/?#]+)/i,
      (_, scheme, host) => scheme + host.replace(/\./g, '[.]'));
  }
  if (type === 'Email') {
    const [user, domain = ''] = v.split('@');
    return `${user}[@]${domain.replace(/\./g, '[.]')}`;
  }
  return v.replace(/\./g, '[.]');
}

function shorten(s, n = 60) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

const SEV_BADGE = {
  critical: 'badge-red', high: 'badge-red', medium: 'badge-yellow',
  low: 'badge-gray', info: 'badge-blue',
};
function sevBadge(sev) {
  const s = String(sev || 'info').toLowerCase();
  return `<span class="badge ${SEV_BADGE[s] || 'badge-gray'}">${esc(s[0].toUpperCase() + s.slice(1))}</span>`;
}

function authClass(v) {
  if (v === 'pass') return 'pass';
  if (['fail', 'softfail', 'permerror'].includes(v)) return 'fail';
  return 'warn';
}

function download(filename, mime, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function api(path, body) {
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `${res.status}`;
    try { detail = (await res.json()).detail || detail; } catch { /* not JSON */ }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function iocKey(i) { return `${i.type}|${String(i.indicator).toLowerCase()}`; }

// Auto IOCs (minus dismissed) + custom URLs + manual entries, deduplicated.
// The email parser rates a URL IOC only by its rule flags; if the ML model
// (or a blocklist) says the link is high risk, the IOC should say so too.
function withModelSeverity(ioc) {
  if (ioc.type !== 'URL' || ioc.severity === 'critical') return ioc;
  const ml = state.urlScores[ioc.indicator];
  const listed = state.urlIntel[ioc.indicator]?.blocklists?.listed;
  if (listed || ml?.risk_level === 'high') {
    return { ...ioc, severity: 'critical',
             detail: `${ioc.detail} — ${listed ? 'on a phishing blocklist' : `ML ${Math.round(ml.phishing_probability * 100)}% phishing`}` };
  }
  return ioc;
}

function allIocs() {
  const out = [];
  const seen = new Set();
  const push = (ioc) => {
    const k = iocKey(ioc);
    if (!seen.has(k)) { seen.add(k); out.push(ioc); }
  };
  (state.analysis?.iocs || [])
    .filter(i => !state.removedIocs.includes(iocKey(i)))
    .map(withModelSeverity)
    .forEach(push);
  state.customUrls.forEach(u => push({
    type: 'URL', indicator: u, detail: 'Added by analyst', severity: 'medium', source: 'manual',
  }));
  state.manualIocs.forEach(push);
  return out;
}

function allUrls() {
  const parsed = state.analysis?.urls || [];
  const custom = state.customUrls
    .filter(u => !parsed.some(p => p.url === u))
    .map(u => ({ url: u, link_text: '', flags: [], source: 'analyst', domain: '' }));
  return [...parsed, ...custom];
}

// ─── ACTIONS ─────────────────────────────────────────────
// Buttons declare data-action="name" (+ data-* args); one delegated
// listener dispatches here. No inline onclick strings.
const actions = {
  goto: el => setStage(Number(el.dataset.stage)),
  next: () => setStage(state.stage + 1),
  prev: () => setStage(state.stage - 1),

  async analyze() {
    const ta = document.getElementById('email-input');
    if (ta) state.emailRaw = ta.value;
    if (!state.emailRaw.trim()) return flash('Paste an email or load a file first.');
    busy = true; render();
    try {
      state.analysis = await api('/analyze/email', { raw: state.emailRaw });
      state.urlScores = {};
      state.urlIntel = {};
      state.enrichment = { domains: {}, ips: {} };
      state.removedIocs = [];
      state.ai = {};
      state.aiPreview = null;
      state.stage = 1;
      scoreUrls();
      enrichAll();
    } catch (e) {
      flash(e.status ? `Analysis failed: ${e.message}`
        : 'Could not reach the backend. Start it with: uvicorn api:app --port 8000 (in phishing-detector/backend)');
    } finally {
      busy = false; saveState(); render();
    }
  },

  async loadSample(el) {
    try {
      const res = await fetch(`samples/${el.dataset.file}`);
      if (!res.ok) throw new Error(res.status);
      state.emailRaw = await res.text();
      state.sourceName = el.dataset.file;
      saveState(); render();
    } catch {
      flash('Could not load the sample — open PhishIntel through the backend at /app.');
    }
  },

  pickFile: () => document.getElementById('file-input')?.click(),

  addUrl() {
    const input = document.getElementById('new-url');
    const v = input?.value.trim();
    if (!v) return;
    const url = /^[a-z]+:\/\//i.test(v) ? v : 'http://' + v;
    if (!state.customUrls.includes(url)) state.customUrls.push(url);
    saveState(); render(); scoreUrls();
  },

  addIoc() {
    const val = document.getElementById('ioc-val').value.trim();
    if (!val) return;
    state.manualIocs.push({
      type: document.getElementById('ioc-type').value,
      indicator: val,
      detail: document.getElementById('ioc-detail').value.trim() || 'Added by analyst',
      severity: document.getElementById('ioc-sev').value,
      source: 'manual',
    });
    saveState(); render();
  },

  removeIoc(el) {
    const key = el.dataset.key;
    state.manualIocs = state.manualIocs.filter(i => iocKey(i) !== key);
    state.customUrls = state.customUrls.filter(u => iocKey({ type: 'URL', indicator: u }) !== key);
    if (!state.removedIocs.includes(key)) state.removedIocs.push(key);
    saveState(); render();
  },

  restoreIocs() { state.removedIocs = []; saveState(); render(); },

  toggleDefang(el) { state.defang = el.checked; saveState(); },

  ai: el => aiAnalyze(el.dataset.target, el.dataset.kind),
  aiSend: () => aiSendPreview(),
  aiCancel() { state.aiPreview = null; render(); },
  toggleRedact(el) { state.aiRedact = el.checked; state.aiPreview = null; saveState(); render(); },

  exportCsv() {
    const rows = allIocs().map(i => [i.type, fmtIoc(i), i.detail, i.severity, i.source]);
    const csv = [['Type', 'Indicator', 'Detail', 'Severity', 'Source'], ...rows]
      .map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n');
    download(`${state.caseId}-iocs.csv`, 'text/csv', csv);
  },

  exportJson() {
    const out = {
      case_id: state.caseId,
      created_at: state.createdAt,
      exported_at: new Date().toISOString(),
      verdict: state.analysis?.verdict,
      headers: state.analysis?.headers,
      auth: state.analysis?.auth,
      findings: state.analysis?.findings,
      urls: allUrls().map(u => ({ ...u, ml: state.urlScores[u.url] || null, intel: state.urlIntel[u.url] || null })),
      attachments: state.analysis?.attachments,
      intel_findings: intelFindings(),
      score_breakdown: scoreRows().map(r => ({ title: r.title, severity: r.severity, points: r.points, source: r.from })),
      attack: attackSummary(),
      qr_codes: state.analysis?.qr_codes,
      html_attachments: state.analysis?.html_attachments,
      enrichment: state.enrichment,
      iocs: allIocs().map(i => ({ ...i, indicator: fmtIoc(i) })),
      defanged: state.defang,
    };
    download(`${state.caseId}.json`, 'application/json', JSON.stringify(out, null, 2));
  },

  exportMarkdown() { download(`${state.caseId}-report.md`, 'text/markdown', buildMarkdownReport()); },

  reset() {
    if (!confirm('Start a new investigation? The current case will be cleared.')) return;
    state = newCase(); saveState(); render();
  },
};

function fmtIoc(i) { return state.defang ? defang(i.type, i.indicator) : i.indicator; }

function setStage(i) {
  state.stage = Math.max(0, Math.min(STAGES.length - 1, i));
  saveState(); render();
  window.scrollTo(0, 0);
}

let flashTimer;
function flash(msg) {
  const el = document.getElementById('flash');
  if (!el) return alert(msg);
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { el.hidden = true; }, 6000);
}

// Score every URL with the ML model + blocklists (POST /enrich/url), in parallel.
async function scoreUrls() {
  const pending = allUrls().filter(u => !state.urlScores[u.url]).slice(0, 50);
  await Promise.all(pending.map(async u => {
    try {
      const r = await api('/enrich/url', { url: u.url });
      state.urlScores[u.url] = r.ml;
      state.urlIntel[u.url] = { blocklists: r.blocklists, urlhaus: r.urlhaus, virustotal: r.virustotal };
    } catch (e) {
      state.urlScores[u.url] = { error: e.message };
    }
  }));
  if (pending.length) { saveState(); render(); }
}

// Domain age / DNS for every Domain IOC, ASN / owner for every IP IOC.
async function enrichAll() {
  const e = state.enrichment;
  const iocs = allIocs();
  const domains = [...new Set(iocs.filter(i => i.type === 'Domain').map(i => i.indicator.toLowerCase()))]
    .filter(d => !e.domains[d]).slice(0, 25);
  const ips = [...new Set(iocs.filter(i => i.type === 'IP').map(i => i.indicator))]
    .filter(ip => !e.ips[ip]).slice(0, 25);
  if (!domains.length && !ips.length) return;
  domains.forEach(d => { e.domains[d] = { loading: true }; });
  ips.forEach(ip => { e.ips[ip] = { loading: true }; });
  render();
  await Promise.all([
    ...domains.map(async d => {
      try { e.domains[d] = await api('/enrich/domain', { domain: d }); }
      catch (err) { e.domains[d] = { error: err.message }; }
    }),
    ...ips.map(async ip => {
      try { e.ips[ip] = await api('/enrich/ip', { ip }); }
      catch (err) { e.ips[ip] = { error: err.message }; }
    }),
  ]);
  saveState(); render();
}

// Findings that come from enrichment rather than the email itself.
function intelFindings() {
  const out = [];
  const add = (severity, title, detail) => out.push({ severity, category: 'intel', title, detail });
  for (const [url, intel] of Object.entries(state.urlIntel)) {
    const b = intel.blocklists || {};
    const where = [
      b.local && (b.local.url_match || b.local.host_match) && 'local phishing database',
      b.openphish && (b.openphish.url_match || b.openphish.host_match) && 'OpenPhish feed',
    ].filter(Boolean);
    if (where.length) add('high', 'URL is on a phishing blocklist', `${url} — ${where.join(', ')}`);
    if (intel.urlhaus?.listed) add('high', 'URL listed on URLhaus', `${url} — ${intel.urlhaus.threat || 'malicious'}`);
    if (intel.virustotal?.malicious) add('high', 'VirusTotal detections',
      `${url} — ${intel.virustotal.malicious}/${intel.virustotal.total} engines flag it as malicious`);
  }
  const senderDomain = (state.analysis?.iocs || []).find(i => i.detail === 'Sender domain')?.indicator;
  for (const [d, info] of Object.entries(state.enrichment.domains)) {
    const r = info.rdap || {};
    if (r.found === false) {
      add('medium', 'Domain is not registered', `${d} has no registration record — taken down or never existed`);
    } else if (r.age_days != null && r.age_days < 30) {
      add('high', 'Newly registered domain', `${d} was registered ${r.age_days} days ago`);
    } else if (r.age_days != null && r.age_days < 180) {
      add('medium', 'Recently registered domain', `${d} was registered ${r.age_days} days ago`);
    }
    if (d === senderDomain && info.dns?.exists && Array.isArray(info.dns.mx) && !info.dns.mx.length)
      add('low', 'Sender domain has no MX record', `${d} cannot receive mail — typical of throwaway sending domains`);
  }
  return out;
}

const SEV_WEIGHT = { high: 3, medium: 2, low: 1, info: 0 };

function allFindings() {
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return [...(state.analysis?.findings || []), ...intelFindings()]
    .sort((a, b) => order[a.severity] - order[b.severity]);
}

// Email-analysis score plus enrichment findings, same thresholds as the backend.
function combinedVerdict() {
  const base = state.analysis.verdict;
  const score = base.score + intelFindings().reduce((n, f) => n + SEV_WEIGHT[f.severity], 0);
  if (score >= 8) return { level: 'high', label: 'Likely phishing', score };
  if (score >= 4) return { level: 'medium', label: 'Suspicious', score };
  return { level: 'low', label: 'No strong phishing indicators', score };
}

// ─── AI ──────────────────────────────────────────────────
const PROVIDER_LABELS = { template: 'Built-in (offline)', ollama: 'Ollama (local)', gemini: 'Gemini (cloud)' };

function providerReady(p) {
  return p === 'template' || !!config?.ai?.[p]?.available;
}

async function aiAnalyze(targetId, kind) {
  const provider = providerReady(state.aiProvider) ? state.aiProvider : 'template';
  if (provider === 'gemini') {
    // Cloud provider: show exactly what would be sent and wait for confirmation.
    try {
      const res = await api('/ai/summarize', { kind, case: aiContext(), provider, redact: state.aiRedact, dry_run: true });
      state.aiPreview = { target: targetId, kind, prompt: res.prompt };
      render();
    } catch (e) {
      flash(`Could not build the prompt: ${e.message}`);
    }
    return;
  }
  await runAi(targetId, kind, provider);
}

function aiSendPreview() {
  const p = state.aiPreview;
  if (!p) return;
  state.aiPreview = null;
  runAi(p.target, p.kind, 'gemini');
}

async function runAi(targetId, kind, provider) {
  state.ai[targetId] = { loading: true, provider };
  render();
  try {
    const res = await api('/ai/summarize', { kind, case: aiContext(), provider, redact: state.aiRedact });
    state.ai[targetId] = { text: res.text, provider: res.provider, model: res.model };
  } catch (e) {
    state.ai[targetId] = { error: `${PROVIDER_LABELS[provider]} failed: ${e.message}`, provider };
  }
  saveState(); render();
}

function aiContext() {
  const a = state.analysis || {};
  return {
    headers: a.headers, auth: a.auth, hops: a.hops, verdict: combinedVerdict(),
    findings: allFindings(),
    urls: allUrls().map(u => ({
      url: u.url, flags: u.flags, link_text: u.link_text,
      ml: state.urlScores[u.url], intel: { listed: state.urlIntel[u.url]?.blocklists?.listed },
    })),
    attachments: a.attachments, iocs: allIocs(),
    enrichment: compactEnrichment(),
  };
}

function compactEnrichment() {
  const domains = {};
  for (const [d, e] of Object.entries(state.enrichment.domains)) {
    if (e.loading || e.error) continue;
    domains[d] = {
      rdap: e.rdap && { found: e.rdap.found, age_days: e.rdap.age_days, registered: e.rdap.registered, registrar: e.rdap.registrar },
      has_mx: e.dns?.exists && Array.isArray(e.dns.mx) ? e.dns.mx.length > 0 : null, // unknown if domain does not resolve
    };
  }
  const ips = {};
  for (const [ip, e] of Object.entries(state.enrichment.ips)) {
    if (!e.loading && !e.error) ips[ip] = { asn: e.asn, as_name: e.as_name, country: e.country, ptr: e.ptr };
  }
  return { domains, ips };
}

// ─── RENDER ──────────────────────────────────────────────
const STAGE_FNS = [stageSample, stageHeaders, stageUrls, stageIocs, stageInfra, stageReport];

function render() {
  document.getElementById('case-id').textContent = state.caseId;
  document.getElementById('stages').innerHTML = STAGES.map((label, i) => `
    <button class="stage-btn ${i === state.stage ? 'active' : i < state.stage ? 'done' : ''}"
            data-action="goto" data-stage="${i}">
      ${i < state.stage ? '✓' : i + 1} · ${label}
    </button>`).join('');
  document.getElementById('progress').style.width =
    Math.round(((state.stage + 1) / STAGES.length) * 100) + '%';

  const needsAnalysis = state.stage > 0 && !state.analysis;
  document.getElementById('panel').innerHTML =
    (needsAnalysis ? noAnalysisPanel() : STAGE_FNS[state.stage]()) +
    '<div id="flash" class="flash" hidden></div>';
}

function navRow({ back = true, nextLabel = 'Continue →', extra = '' } = {}) {
  return `
    <div class="nav-row">
      ${back ? '<button class="btn btn-sec" data-action="prev">← Back</button>' : '<span></span>'}
      <div style="display:flex; gap:8px">${extra}
        ${nextLabel ? `<button class="btn btn-primary" data-action="next">${nextLabel}</button>` : ''}
      </div>
    </div>`;
}

function providerSelect() {
  const opts = ['template', 'ollama', 'gemini'].map(p => {
    const ready = providerReady(p);
    const info = config?.ai?.[p] || {};
    const note = p === 'ollama' ? (ready ? ` · ${info.model}` : ' · not running')
      : p === 'gemini' ? (ready ? '' : ' · no key in .env') : '';
    return `<option value="${p}" ${state.aiProvider === p ? 'selected' : ''} ${ready ? '' : 'disabled'}>${PROVIDER_LABELS[p]}${esc(note)}</option>`;
  }).join('');
  return `<select class="ai-select" data-action="setProvider" aria-label="AI engine">${opts}</select>`;
}

function aiBlock(id, kind, label = '✦ AI analysis') {
  const r = state.ai[id];
  const preview = state.aiPreview?.target === id ? state.aiPreview : null;
  let body = 'Click AI analysis for an analyst-style summary of this stage.';
  let cls = 'loading';
  if (r?.loading) body = `Generating with ${PROVIDER_LABELS[r.provider]}…`;
  else if (r?.error) body = r.error;
  else if (r?.text) { body = r.text; cls = ''; }
  const source = r?.text ? `<div class="ai-source">${esc(PROVIDER_LABELS[r.provider] || r.provider)}${r.model ? ' · ' + esc(r.model) : ''}</div>` : '';
  const cloud = state.aiProvider === 'gemini' && providerReady('gemini');
  return `
    <div style="margin-top:14px">
      <div id="${id}" class="ai-box ${cls}">${esc(body)}${source}</div>
      ${preview ? `
        <div class="ai-preview">
          <p><strong>Review before sending to Google Gemini.</strong> This exact text leaves your machine
            ${state.aiRedact ? '(recipient details and URL parameters redacted)' : '<span class="auth-fail">(NOT redacted)</span>'}.
            The email body is never sent.</p>
          <pre>${esc(preview.prompt)}</pre>
          <div style="display:flex; gap:8px">
            <button class="btn btn-primary" data-action="aiSend">Send to Gemini</button>
            <button class="btn btn-sec" data-action="aiCancel">Cancel</button>
          </div>
        </div>` : ''}
      <div class="ai-controls">
        <button class="btn btn-sec" data-action="ai" data-target="${id}" data-kind="${kind}" ${r?.loading ? 'disabled' : ''}>${label}</button>
        ${providerSelect()}
        ${cloud ? `<label class="check-label"><input type="checkbox" data-action="toggleRedact" ${state.aiRedact ? 'checked' : ''}> Redact personal data</label>` : ''}
      </div>
    </div>`;
}

function verdictBanner() {
  const v = combinedVerdict();
  const n = allFindings().filter(f => f.severity !== 'info').length;
  return `
    <div class="verdict verdict-${esc(v.level)}">
      <strong>${esc(v.label)}</strong>
      <span>risk score ${esc(v.score)} · ${n} findings</span>
    </div>`;
}

// ─── MITRE ATT&CK ────────────────────────────────────────
// Mapping comes from the backend (attack.py via /config) so the email
// findings and the UI's own intel findings use one table.
function attackIds(f) {
  return f.attack?.length ? f.attack : (config?.attack?.by_title?.[f.title] || []);
}
function attackName(id) { return config?.attack?.techniques?.[id] || id; }
function attackUrl(id) { return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`; }

function attackSummary() {
  const byId = new Map();
  for (const f of allFindings()) {
    for (const id of attackIds(f)) {
      if (!byId.has(id)) byId.set(id, { id, name: attackName(id), url: attackUrl(id), evidence: [] });
      const t = byId.get(id);
      if (!t.evidence.includes(f.title)) t.evidence.push(f.title);
    }
  }
  return [...byId.values()].sort((a, b) => b.evidence.length - a.evidence.length || a.id.localeCompare(b.id));
}

function attackChips(f) {
  const ids = attackIds(f);
  if (!ids.length) return '';
  return `<div class="attack-chips">${ids.map(id =>
    `<a class="attack-chip" href="${esc(attackUrl(id))}" target="_blank" rel="noopener" title="${esc(attackName(id))}">${esc(id)}</a>`).join('')}</div>`;
}

function findingsList(filter) {
  const items = allFindings().filter(filter);
  if (!items.length) return '<p class="muted">No issues found in this area.</p>';
  return items.map(f => `
    <div class="check-row">
      <div class="check-icon ${f.severity === 'high' ? 'icon-fail' : f.severity === 'info' ? 'icon-pass' : 'icon-warn'}">
        ${f.severity === 'high' ? '✕' : f.severity === 'info' ? 'i' : '!'}</div>
      <div><strong>${esc(f.title)}</strong><div class="muted break">${esc(f.detail)}</div>${attackChips(f)}</div>
      <span style="margin-left:auto">${sevBadge(f.severity)}</span>
    </div>`).join('');
}

function noAnalysisPanel() {
  return `
    <div class="panel">
      <p class="panel-title">No email analysed yet</p>
      <p class="panel-sub">Paste or upload an email in Stage 1 and click Analyze — every later stage is built from that analysis.</p>
      <button class="btn btn-primary" data-action="goto" data-stage="0">← Go to Stage 1</button>
    </div>`;
}

// STAGE 1 — sample
function stageSample() {
  return `
    <div class="panel">
      <p class="panel-title">Stage 1 — Get a phishing sample</p>
      <p class="panel-sub">Paste the raw email (with full headers) or drop an <code>.eml</code> file.
        In Outlook/Gmail use “Show original” / “View source” to get the headers.</p>
      <div id="dropzone" class="dropzone">
        <span>Drop an <strong>.eml</strong> / <strong>.txt</strong> file here or</span>
        <button class="btn btn-sec" data-action="pickFile">Choose file</button>
        <input type="file" id="file-input" accept=".eml,.txt,message/rfc822" hidden>
        ${state.sourceName ? `<span class="muted">Loaded: ${esc(state.sourceName)}</span>` : ''}
      </div>
      <textarea id="email-input" placeholder="Paste full email with headers...">${esc(state.emailRaw)}</textarea>
      <div class="sample-row">
        <span class="muted">Demo samples:</span>
        ${SAMPLES.map(s => `<button class="btn btn-sec btn-sm" data-action="loadSample" data-file="${esc(s.file)}">${esc(s.label)}</button>`).join('')}
      </div>
      ${state.analysis ? `<div style="margin-top:14px">${verdictBanner()}</div>` : ''}
      <div class="nav-row">
        <span class="muted">${state.analysis ? 'Re-analyse after editing to refresh every stage.' : ''}</span>
        <div style="display:flex; gap:8px">
          ${state.analysis ? '<button class="btn btn-sec" data-action="next">Skip to results →</button>' : ''}
          <button class="btn btn-primary" data-action="analyze" ${busy ? 'disabled' : ''}>
            ${busy ? 'Analysing…' : 'Analyze email →'}</button>
        </div>
      </div>
    </div>`;
}

// STAGE 2 — headers
function stageHeaders() {
  const { headers: h, auth, hops } = state.analysis;
  const metric = (label, v) => `
    <div class="metric"><div class="label">${label}</div>
      <div class="value auth-${authClass(v)}">${esc(String(v).toUpperCase())}</div></div>`;
  const spam = auth.spam_score != null ? auth.spam_score : (auth.spam_flagged ? 'YES' : '—');
  const row = (k, v, cls = '') => v ? `<tr><td class="muted" style="width:28%">${k}</td><td class="${cls} break">${esc(v)}</td></tr>` : '';
  const hopRows = hops.map((hop, i) => `
    <tr>
      <td>${i + 1}</td>
      <td class="mono break">${esc(hop.from || '—')}</td>
      <td class="mono">${esc(hop.ip || '—')} ${hop.ip ? (hop.internal ? '<span class="badge badge-gray">internal</span>' : '<span class="badge badge-blue">external</span>') : ''}</td>
      <td class="mono break">${esc(hop.by || '—')}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 2 — Email header analysis</p>
      <p class="panel-sub">Sender identity, authentication results and the mail route, parsed from the raw headers.</p>
      ${verdictBanner()}
      <div class="metrics">
        ${metric('SPF', auth.spf)}${metric('DKIM', auth.dkim)}${metric('DMARC', auth.dmarc)}
        <div class="metric"><div class="label">Spam score</div>
          <div class="value ${auth.spam_flagged ? 'auth-warn' : ''}">${esc(spam)}</div></div>
      </div>
      <table style="margin-bottom:16px">
        ${row('From', h.from_name ? `${h.from_name} <${h.from_address}>` : h.from_address, 'mono')}
        ${row('Reply-To', h.reply_to, 'mono')}
        ${row('Return-Path', h.return_path, 'mono')}
        ${row('To', h.to.join(', '), 'mono')}
        ${row('Subject', h.subject)}
        ${row('Date', h.date)}
        ${row('Message-ID', h.message_id, 'mono')}
        ${row('X-Mailer', h.x_mailer)}
      </table>
      <p class="section-title">Findings</p>
      ${findingsList(f => ['auth', 'sender', 'routing'].includes(f.category))}
      <p class="section-title">Received chain (oldest first)</p>
      ${hops.length ? `<table><thead><tr><th>#</th><th>From host</th><th>IP</th><th>Received by</th></tr></thead>
        <tbody>${hopRows}</tbody></table>` : '<p class="muted">No Received headers — this looks like a forwarded or copy-pasted message.</p>'}
      ${aiBlock('ai-header', 'headers')}
      ${navRow()}
    </div>`;
}

// STAGE 3 — URLs & attachments
function mlCell(url) {
  const s = state.urlScores[url];
  if (!s) return '<span class="muted">scoring…</span>';
  if (s.error) return `<span class="muted" title="${esc(s.error)}">n/a</span>`;
  const pct = Math.round(s.phishing_probability * 100);
  const cls = { high: 'badge-red', medium: 'badge-yellow', low: 'badge-gray', safe: 'badge-green' }[s.risk_level];
  return `<span class="badge ${cls}">${s.trust_override_applied ? 'trusted' : pct + '%'}</span>`;
}

const SOURCE_LABELS = {
  'text': 'body text', 'html-link': 'HTML link', 'html-form': 'HTML form',
  'qr-code': 'QR code', 'attachment-form': 'attachment form',
  'attachment-redirect': 'attachment redirect', 'attachment-link': 'attachment link', 'analyst': 'added by you',
};

function htmlAttachmentSection() {
  const list = state.analysis.html_attachments || [];
  if (!list.length) return '';
  const yes = (v, label) => v ? `<span class="badge badge-red">${label}</span>` : '';
  return `
    <p class="section-title">HTML attachments <span class="muted">(read as text — never opened or run)</span></p>
    <table style="margin-bottom:14px"><thead><tr><th>File</th><th>What it contains</th></tr></thead><tbody>
    ${list.map(s => `<tr><td class="break">${esc(s.filename)}</td><td>
      ${yes(s.password_field, 'password field')} ${yes(s.external_forms, `${s.external_forms} external form(s)`)}
      ${yes(s.redirects, `${s.redirects} redirect(s)`)} ${s.obfuscated ? '<span class="badge badge-yellow">obfuscated script</span>' : ''}
      ${s.links ? `<span class="badge badge-gray">${s.links} link(s)</span>` : ''}
      ${!(s.password_field || s.external_forms || s.redirects || s.obfuscated || s.links) ? '<span class="muted">nothing suspicious found</span>' : ''}
    </td></tr>`).join('')}
    </tbody></table>`;
}

function qrSection() {
  const codes = state.analysis.qr_codes || [];
  if (!codes.length) return '';
  return `
    <p class="section-title">QR codes in images <span class="muted">(decoded offline)</span></p>
    <table style="margin-bottom:14px"><thead><tr><th>Image</th><th>Decoded content</th></tr></thead><tbody>
    ${codes.map(q => `<tr><td class="break">${esc(q.image)}</td><td class="mono break">${esc(q.text)}</td></tr>`).join('')}
    </tbody></table>`;
}

function intelCell(url) {
  const i = state.urlIntel[url];
  if (!i) return state.urlScores[url]?.error ? '<span class="muted">n/a</span>' : '<span class="muted">checking…</span>';
  const badges = [];
  const b = i.blocklists || {};
  if (b.local?.url_match || b.local?.host_match) badges.push(`<span class="badge badge-red" title="Phishing.Database list from ${esc(b.local.list_date)}">local list</span>`);
  if (b.openphish?.url_match || b.openphish?.host_match) badges.push('<span class="badge badge-red">OpenPhish</span>');
  if (i.urlhaus?.listed) badges.push('<span class="badge badge-red">URLhaus</span>');
  if (i.virustotal?.seen) badges.push(`<span class="badge ${i.virustotal.malicious ? 'badge-red' : 'badge-green'}">VT ${i.virustotal.malicious}/${i.virustotal.total}</span>`);
  return badges.join(' ') || '<span class="badge badge-gray">not listed</span>';
}

function stageUrls() {
  const urls = allUrls();
  const atts = state.analysis.attachments;
  const rows = urls.map(u => `
    <tr>
      <td class="mono break" title="${esc(u.url)}">${esc(shorten(u.url, 70))}
        ${u.link_text ? `<div class="muted">shown as: “${esc(shorten(u.link_text, 60))}”</div>` : ''}
        ${(state.urlScores[u.url]?.reasons || []).length ? `<ul class="ml-reasons">${state.urlScores[u.url].reasons
          .map(r => `<li>${esc(r.reason)}</li>`).join('')}</ul>` : ''}</td>
      <td>${(u.flags || []).map(f => `<span class="badge ${f === 'no-https' ? 'badge-gray' : 'badge-yellow'}">${esc(f)}</span>`).join(' ') || '<span class="muted">—</span>'}</td>
      <td>${mlCell(u.url)}</td>
      <td>${intelCell(u.url)}</td>
      <td class="muted">${esc(SOURCE_LABELS[u.source] || u.source)}${u.found_in ? `<div class="break">${esc(u.found_in)}</div>` : ''}</td>
    </tr>`).join('');
  const attRows = atts.map(a => `
    <tr>
      <td class="break">${esc(a.filename)}</td>
      <td class="mono">${esc(a.content_type)}</td>
      <td>${(a.size / 1024).toFixed(1)} KB</td>
      <td class="mono break" title="MD5 ${esc(a.md5)}">${esc(a.sha256)}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 3 — URL & attachment analysis</p>
      <p class="panel-sub">Every link found in the text and HTML bodies (defanged links are refanged),
        scored by the phishing-detector ML model.</p>
      ${urls.length ? `<table style="margin-bottom:14px">
        <thead><tr><th>URL</th><th>Flags</th><th>ML score</th><th>Blocklists</th><th>Found in</th></tr></thead>
        <tbody>${rows}</tbody></table>` : '<p class="muted" style="margin-bottom:14px">No URLs found in this email.</p>'}
      <div style="display:flex; gap:8px; margin-bottom:14px;">
        <input id="new-url" placeholder="Add a URL to check..." style="flex:1" />
        <button class="btn btn-sec" data-action="addUrl">+ Add</button>
      </div>
      <p class="section-title">Attachments</p>
      ${atts.length ? `<table style="margin-bottom:14px"><thead><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead>
        <tbody>${attRows}</tbody></table>` : '<p class="muted">No attachments.</p>'}
      ${htmlAttachmentSection()}
      ${qrSection()}
      <p class="section-title">Findings</p>
      ${findingsList(f => ['url', 'attachment', 'content'].includes(f.category) ||
        (f.category === 'intel' && /^URL|VirusTotal/.test(f.title)))}
      ${aiBlock('ai-url', 'urls')}
      ${navRow()}
    </div>`;
}

// STAGE 4 — IOCs
function stageIocs() {
  const iocs = allIocs();
  const rows = iocs.map(i => `
    <tr>
      <td><span class="badge badge-gray">${esc(i.type)}</span></td>
      <td class="mono break">${esc(i.indicator)}</td>
      <td class="muted">${esc(i.detail)}</td>
      <td>${sevBadge(i.severity)}</td>
      <td><button class="btn-icon" title="Remove" data-action="removeIoc" data-key="${esc(iocKey(i))}">✕</button></td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 4 — IOC collection</p>
      <p class="panel-sub">Indicators extracted automatically from the email. Remove false positives, add your own.</p>
      <table style="margin-bottom:14px">
        <thead><tr><th>Type</th><th>Indicator</th><th>Detail</th><th>Severity</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="muted">No IOCs.</td></tr>'}</tbody>
      </table>
      ${state.removedIocs.length ? `<p class="muted" style="margin-bottom:10px">${state.removedIocs.length} removed ·
        <a href="#" data-action="restoreIocs">restore</a></p>` : ''}
      <div class="ioc-form">
        <select id="ioc-type"><option>Domain</option><option>IP</option><option>URL</option><option>Email</option><option>Hash</option></select>
        <input id="ioc-val" placeholder="Indicator value" />
        <input id="ioc-detail" placeholder="Description" />
        <select id="ioc-sev"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select>
        <button class="btn btn-sec" data-action="addIoc">+ Add</button>
      </div>
      <label class="check-label"><input type="checkbox" data-action="toggleDefang" ${state.defang ? 'checked' : ''}>
        Defang indicators in exports (hxxp, [.]) — safe to paste into tickets and chat</label>
      <div style="margin-top:8px; display:flex; gap:8px;">
        <button class="btn btn-sec" data-action="exportCsv">↓ Export CSV</button>
        <button class="btn btn-sec" data-action="exportJson">↓ Export JSON</button>
      </div>
      ${aiBlock('ai-ioc', 'iocs')}
      ${navRow()}
    </div>`;
}

// STAGE 5 — infrastructure
function attackChain() {
  const a = state.analysis;
  const steps = [];
  const sev = a.findings.some(f => f.category === 'sender' && f.severity === 'high');
  steps.push({ icon: '📧', bg: sev ? '#fde8e8' : '#f3f4f6', title: 'Email delivered',
    sub: `${a.headers.from_address || 'unknown sender'}${a.headers.from_name ? ` (“${a.headers.from_name}”)` : ''}` });
  const shorteners = a.urls.filter(u => u.flags.includes('shortener'));
  if (shorteners.length) steps.push({ icon: '🔗', bg: '#fef3c7', title: 'Redirect via URL shortener',
    sub: shorteners.map(u => u.domain).join(', ') });
  const landing = a.urls.filter(u => !u.flags.includes('shortener') && u.source !== 'html-form');
  if (landing.length) steps.push({ icon: '🌐', bg: landing.some(u => u.flags.length > 1 || u.flags.some(f => f !== 'no-https')) ? '#fde8e8' : '#f3f4f6',
    title: 'Landing page', sub: [...new Set(landing.map(u => u.domain))].join(', ') });
  a.attachments.forEach(att => steps.push({ icon: '📎', bg: '#fde8e8', title: 'Attachment opened', sub: att.filename }));
  const forms = a.urls.filter(u => u.source === 'html-form');
  const lure = a.findings.some(f => f.category === 'content') || forms.length;
  if (forms.length || lure) steps.push({ icon: '🔓', bg: '#fde8e8', title: 'Credential / data harvest',
    sub: forms.length ? `form posts to ${forms.map(f => f.domain).join(', ')}` : 'victim asked to enter details' });
  return steps.map((s, i) => `
    ${i ? '<div class="chain-line"></div>' : ''}
    <div class="chain-step"><div class="chain-icon" style="background:${s.bg}">${s.icon}</div>
      <div><strong style="font-size:13px">${esc(s.title)}</strong><br><span class="muted break">${esc(s.sub)}</span></div></div>`).join('');
}

function ageText(days) {
  if (days == null) return '';
  if (days < 60) return `${days} days`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  return `${(days / 365).toFixed(1)} years`;
}

function domainIntel(d) {
  const e = state.enrichment.domains[d.toLowerCase()];
  if (!e || e.loading) return '<span class="muted">looking up…</span>';
  if (e.error) return `<span class="muted">${esc(e.error)}</span>`;
  const r = e.rdap || {};
  const lines = [];
  if (r.found === false) lines.push('<span class="badge badge-yellow">not registered</span>');
  else if (r.error) lines.push(`<span class="muted">${esc(r.error)}</span>`);
  else if (r.age_days != null) {
    const cls = r.age_days < 30 ? 'badge-red' : r.age_days < 180 ? 'badge-yellow' : 'badge-green';
    lines.push(`<span class="badge ${cls}">${ageText(r.age_days)} old</span> <span class="muted">since ${esc((r.registered || '').slice(0, 10))}</span>`);
  }
  if (r.registrar) lines.push(`<span class="muted">Registrar: ${esc(r.registrar)}</span>`);
  const dns = e.dns || {};
  if (dns.exists === false) lines.push('<span class="muted">DNS: domain does not resolve</span>');
  else if (dns.a) lines.push(`<span class="muted">A: ${esc(dns.a.slice(0, 3).join(', ') || 'none')} · MX: ${dns.mx?.length ? 'yes' : 'none'}</span>`);
  return lines.join('<br>') || '<span class="muted">no data</span>';
}

function ipIntel(ip) {
  const e = state.enrichment.ips[ip];
  if (!e || e.loading) return '<span class="muted">looking up…</span>';
  if (e.error) return `<span class="muted">${esc(e.error)}</span>`;
  if (e.private) return '<span class="muted">private / internal address</span>';
  const lines = [];
  if (e.asn) lines.push(`<strong>AS${esc(e.asn)}</strong> ${esc(e.as_name || '')}`);
  if (e.country) lines.push(`<span class="muted">Country: ${esc(e.country)} · ${esc(e.prefix || '')}</span>`);
  if (e.ptr) lines.push(`<span class="muted">rDNS: ${esc(e.ptr)}</span>`);
  return lines.join('<br>') || '<span class="muted">not announced on the internet</span>';
}

function stageInfra() {
  enrichAll(); // no-op once everything is looked up
  const iocs = allIocs().filter(i => ['Domain', 'IP'].includes(i.type));
  const rows = iocs.map(i => `
    <tr>
      <td><span class="badge badge-gray">${esc(i.type)}</span></td>
      <td class="mono break">${esc(i.indicator)}<div class="muted">${esc(i.detail)}</div></td>
      <td>${i.type === 'Domain' ? domainIntel(i.indicator) : ipIntel(i.indicator)}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 5 — Infrastructure tracing</p>
      <p class="panel-sub">Domain age (RDAP), DNS and network owner (ASN) for every domain and IP, plus the
        attack chain reconstructed from the email. No API keys needed.</p>
      <div class="two-col">
        <div>
          <p class="section-title">Domains & IPs</p>
          <table><thead><tr><th>Type</th><th>Indicator</th><th>Intel</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="3" class="muted">None.</td></tr>'}</tbody></table>
        </div>
        <div>
          <p class="section-title">Attack chain</p>
          ${attackChain()}
        </div>
      </div>
      <p class="section-title">Infrastructure findings</p>
      ${findingsList(f => f.category === 'intel' && !/^URL|VirusTotal/.test(f.title))}
      ${aiBlock('ai-infra', 'infra')}
      ${navRow({ nextLabel: 'Generate report →' })}
    </div>`;
}

// STAGE 6 — report
function recommendations() {
  const a = state.analysis;
  const iocs = allIocs();
  const recs = [];
  if (combinedVerdict().level === 'low') {
    recs.push('No strong phishing indicators — release the message if it was quarantined and continue normal monitoring.');
    return recs;
  }
  if (iocs.some(i => i.type === 'Email' || (i.type === 'Domain' && i.detail === 'Sender domain')))
    recs.push('Block the sender address and domain at the email gateway.');
  if (iocs.some(i => i.type === 'URL' || i.detail === 'Linked domain'))
    recs.push('Block the listed URLs and linked domains at the web proxy / DNS filter.');
  if (a.attachments.length)
    recs.push('Add attachment SHA-256 hashes to EDR blocklists and sweep endpoints for them.');
  if ((a.html_attachments || []).some(s => s.password_field || s.external_forms || s.redirects))
    recs.push('Quarantine or block .html / .htm / .svg attachments at the email gateway — they open locally, where URL filtering never sees them.');
  if ((a.qr_codes || []).length)
    recs.push('Warn users not to scan QR codes in emails: the link opens on a personal phone, outside corporate web filtering. Block the decoded URL too.');
  recs.push('Search mail logs for the same sender, originating IP and subject; purge matching messages from all mailboxes.');
  if (a.findings.some(f => /form|credential|password/i.test(f.title + f.detail)))
    recs.push('Identify users who clicked or submitted data; reset their credentials and review sign-in logs.');
  const brand = a.findings.find(f => /imitates a brand|Display-name spoofing/.test(f.title));
  if (brand) recs.push('Warn users about this brand-impersonation campaign and report it to the impersonated brand’s abuse team.');
  recs.push('Import the IOCs into the SIEM and share them with your threat-intel community (MISP / ISAC).');
  return recs;
}

function stageReport() {
  const a = state.analysis;
  const iocs = allIocs();
  const authFails = ['spf', 'dkim', 'dmarc'].filter(k => a.auth[k] !== 'pass').length;
  const highFindings = allFindings().filter(f => f.severity === 'high');
  const rows = iocs.map(i => `
    <tr><td><span class="badge badge-gray">${esc(i.type)}</span></td>
      <td class="mono break">${esc(fmtIoc(i))}</td><td>${sevBadge(i.severity)}</td></tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 6 — Investigation report</p>
      <p class="panel-sub">${esc(a.headers.subject || '(no subject)')} — from ${esc(a.headers.from_address || 'unknown')}</p>
      ${verdictBanner()}
      <div class="metrics">
        <div class="metric"><div class="label">Total IOCs</div><div class="value">${iocs.length}</div></div>
        <div class="metric"><div class="label">Critical / High</div><div class="value auth-fail">${iocs.filter(i => ['critical', 'high'].includes(i.severity)).length}</div></div>
        <div class="metric"><div class="label">Auth not passing</div><div class="value ${authFails ? 'auth-fail' : 'auth-pass'}">${authFails}/3</div></div>
        <div class="metric"><div class="label">High findings</div><div class="value ${highFindings.length ? 'auth-fail' : ''}">${highFindings.length}</div></div>
      </div>
      <p class="section-title">Key findings</p>
      ${findingsList(f => f.severity === 'high' || f.severity === 'medium')}
      ${scoreBreakdownSection()}
      ${attackSection()}
      <p class="section-title">Recommended actions</p>
      ${recommendations().map((r, i) => `<div class="rec-item"><div class="rec-num">${i + 1}</div><div>${esc(r)}</div></div>`).join('')}
      ${aiBlock('ai-exec', 'executive', '✦ Generate executive summary')}
      <p class="section-title">Indicators ${state.defang ? '(defanged)' : ''}</p>
      <table style="margin-bottom:16px"><thead><tr><th>Type</th><th>Indicator</th><th>Severity</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3" class="muted">No IOCs.</td></tr>'}</tbody></table>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn btn-primary" data-action="exportMarkdown">↓ Report (Markdown)</button>
        <button class="btn btn-sec" data-action="exportJson">↓ Case (JSON)</button>
        <button class="btn btn-sec" data-action="exportCsv">↓ IOCs (CSV)</button>
      </div>
      ${navRow({ nextLabel: '', extra: '<button class="btn btn-sec" data-action="reset">↺ New investigation</button>' })}
    </div>`;
}

// How the risk score was reached: every finding's points, email vs. intel.
function scoreRows() {
  return allFindings().filter(f => SEV_WEIGHT[f.severity] > 0)
    .map(f => ({ ...f, points: SEV_WEIGHT[f.severity], from: f.category === 'intel' ? 'threat intel' : 'email analysis' }));
}

function scoreBreakdownSection() {
  const rows = scoreRows();
  const v = combinedVerdict();
  const sub = from => rows.filter(r => r.from === from).reduce((n, r) => n + r.points, 0);
  return `
    <details class="score-box">
      <summary><strong>How the risk score was calculated</strong> — ${v.score} points → ${esc(v.label)}</summary>
      <p class="muted" style="margin:8px 0">Each finding adds points by severity: high 3, medium 2, low 1.
        8 or more = <strong>Likely phishing</strong>, 4–7 = <strong>Suspicious</strong>, under 4 = no strong indicators.</p>
      <table><thead><tr><th>Finding</th><th>Source</th><th>Severity</th><th style="text-align:right">Points</th></tr></thead><tbody>
        ${rows.map(r => `<tr><td>${esc(r.title)}</td><td class="muted">${r.from}</td><td>${sevBadge(r.severity)}</td>
          <td style="text-align:right">+${r.points}</td></tr>`).join('')}
        <tr class="score-total"><td colspan="3">Email analysis ${sub('email analysis')} + threat intel ${sub('threat intel')}</td>
          <td style="text-align:right">${v.score}</td></tr>
      </tbody></table>
    </details>`;
}

function attackSection() {
  const techniques = attackSummary();
  if (!techniques.length) return '';
  return `
    <p class="section-title">MITRE ATT&amp;CK techniques <span class="muted">(Enterprise ${esc(config?.attack?.version || 'v20')})</span></p>
    <table style="margin-bottom:14px"><thead><tr><th>Technique</th><th>Evidence in this case</th></tr></thead><tbody>
      ${techniques.map(t => `<tr>
        <td style="white-space:nowrap"><a href="${esc(t.url)}" target="_blank" rel="noopener" class="mono">${esc(t.id)}</a>
          <div style="font-size:12px">${esc(t.name)}</div></td>
        <td class="muted">${t.evidence.map(esc).join('<br>')}</td></tr>`).join('')}
    </tbody></table>`;
}

function buildMarkdownReport() {
  const a = state.analysis;
  const h = a.headers;
  const md = [];
  const cell = v => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  md.push(`# Phishing Investigation Report — ${state.caseId}`, '');
  md.push(`**Generated:** ${new Date().toLocaleString()}  `);
  const v = combinedVerdict();
  md.push(`**Verdict:** ${v.label} (risk score ${v.score})`, '');
  md.push('## Email', '');
  md.push(`| Field | Value |`, `|---|---|`);
  md.push(`| From | ${cell(h.from_name ? `${h.from_name} <${h.from_address}>` : h.from_address)} |`);
  if (h.reply_to) md.push(`| Reply-To | ${cell(h.reply_to)} |`);
  if (h.return_path) md.push(`| Return-Path | ${cell(h.return_path)} |`);
  md.push(`| To | ${cell(h.to.join(', '))} |`, `| Subject | ${cell(h.subject)} |`, `| Date | ${cell(h.date)} |`);
  md.push(`| SPF / DKIM / DMARC | ${a.auth.spf} / ${a.auth.dkim} / ${a.auth.dmarc} |`, '');
  md.push('## Findings', '');
  allFindings().forEach(f => md.push(`- **[${f.severity.toUpperCase()}] ${f.title}** — ${f.detail}`
    + (attackIds(f).length ? ` _(ATT&CK: ${attackIds(f).join(', ')})_` : '')));
  md.push('');
  const rows = scoreRows();
  md.push('## Score breakdown', '', 'High = 3, medium = 2, low = 1 point. ≥ 8 likely phishing, 4–7 suspicious.', '',
    '| Finding | Source | Severity | Points |', '|---|---|---|---:|');
  rows.forEach(r => md.push(`| ${cell(r.title)} | ${r.from} | ${r.severity} | +${r.points} |`));
  md.push(`| **Total** | | | **${v.score}** |`, '');
  const techniques = attackSummary();
  if (techniques.length) {
    md.push(`## MITRE ATT&CK (Enterprise ${config?.attack?.version || 'v20'})`, '', '| Technique | Name | Evidence |', '|---|---|---|');
    techniques.forEach(t => md.push(`| [${t.id}](${t.url}) | ${cell(t.name)} | ${cell(t.evidence.join('; '))} |`));
    md.push('');
  }
  if ((a.qr_codes || []).length) {
    md.push('## QR codes', '', '| Image | Decoded content |', '|---|---|');
    a.qr_codes.forEach(q => md.push(`| ${cell(q.image)} | \`${cell(fmtIoc({ type: 'URL', indicator: q.text }))}\` |`));
    md.push('');
  }
  const enr = compactEnrichment();
  if (Object.keys(enr.domains).length || Object.keys(enr.ips).length) {
    md.push('## Infrastructure', '', '| Indicator | Details |', '|---|---|');
    for (const [d, e] of Object.entries(enr.domains)) {
      const r = e.rdap || {};
      const info = r.found === false ? 'not registered'
        : r.age_days != null ? `registered ${(r.registered || '').slice(0, 10)} (${ageText(r.age_days)} old), ${r.registrar || 'unknown registrar'}` : 'no RDAP data';
      md.push(`| \`${cell(fmtIoc({ type: 'Domain', indicator: d }))}\` | ${cell(info)}${e.has_mx === false ? ', no MX record' : ''} |`);
    }
    for (const [ip, e] of Object.entries(enr.ips)) {
      md.push(`| \`${cell(fmtIoc({ type: 'IP', indicator: ip }))}\` | ${e.asn ? cell(`AS${e.asn} ${e.as_name || ''}${e.country && !(e.as_name || '').endsWith(e.country) ? ', ' + e.country : ''}`) : 'not announced'} |`);
    }
    md.push('');
  }
  const urls = allUrls();
  if (urls.length) {
    md.push('## URLs', '', '| URL | Flags | ML phishing score |', '|---|---|---|');
    urls.forEach(u => {
      const s = state.urlScores[u.url];
      const score = !s || s.error ? 'n/a' : s.trust_override_applied ? 'trusted domain' : `${Math.round(s.phishing_probability * 100)}% (${s.risk_level})`;
      md.push(`| \`${cell(fmtIoc({ type: 'URL', indicator: u.url }))}\` | ${cell((u.flags || []).join(', ') || '—')} | ${score} |`);
    });
    md.push('');
  }
  if (a.attachments.length) {
    md.push('## Attachments', '', '| File | Type | SHA-256 |', '|---|---|---|');
    a.attachments.forEach(x => md.push(`| ${cell(x.filename)} | ${x.content_type} | \`${x.sha256}\` |`));
    md.push('');
  }
  md.push(`## Indicators of compromise${state.defang ? ' (defanged)' : ''}`, '', '| Type | Indicator | Severity | Detail |', '|---|---|---|---|');
  allIocs().forEach(i => md.push(`| ${i.type} | \`${cell(fmtIoc(i))}\` | ${i.severity} | ${cell(i.detail)} |`));
  md.push('', '## Recommended actions', '');
  recommendations().forEach((r, i) => md.push(`${i + 1}. ${r}`));
  const exec = state.ai['ai-exec'];
  if (exec?.text) md.push('', '## Executive summary', '', exec.text,
    '', `_Generated by ${PROVIDER_LABELS[exec.provider] || exec.provider}${exec.model ? ` (${exec.model})` : ''}._`);
  md.push('');
  return md.join('\n');
}

// ─── EVENTS ──────────────────────────────────────────────
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el || el.type === 'checkbox') return;
  if (el.tagName === 'A') e.preventDefault();
  actions[el.dataset.action]?.(el);
});

document.addEventListener('change', e => {
  const el = e.target;
  if (el.type === 'checkbox' && el.dataset.action) actions[el.dataset.action]?.(el);
  if (el.dataset.action === 'setProvider') {
    state.aiProvider = el.value;
    state.providerChosen = true;
    state.aiPreview = null;
    saveState(); render();
  }
  if (el.id === 'file-input' && el.files[0]) readFile(el.files[0]);
});

// Keep the textarea in state without re-rendering on every keystroke.
document.addEventListener('input', e => {
  if (e.target.id === 'email-input') { state.emailRaw = e.target.value; saveState(); }
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  if (e.target.id === 'new-url') actions.addUrl();
  if (e.target.id === 'ioc-val' || e.target.id === 'ioc-detail') actions.addIoc();
});

['dragover', 'dragleave', 'drop'].forEach(type => document.addEventListener(type, e => {
  const zone = e.target.closest?.('#dropzone');
  if (!zone) return;
  e.preventDefault();
  zone.classList.toggle('drag', type === 'dragover');
  if (type === 'drop' && e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]);
}));

const MAX_FILE_BYTES = 10 * 1024 * 1024;
function readFile(file) {
  if (file.size > MAX_FILE_BYTES) return flash('File is larger than 10 MB.');
  const reader = new FileReader();
  reader.onload = () => {
    state.emailRaw = reader.result;
    state.sourceName = file.name;
    saveState(); render();
  };
  reader.readAsText(file);
}

// ─── START ───────────────────────────────────────────────
// Opened from the browser extension ("Investigate in PhishIntel"):
// /app/#url=<encoded> starts a fresh case for that one URL.
function urlFromHash() {
  const m = location.hash.match(/^#url=(.+)$/);
  if (!m) return null;
  history.replaceState(null, '', location.pathname); // don't re-trigger on refresh
  try {
    const url = decodeURIComponent(m[1]);
    return /^https?:\/\//i.test(url) ? url : null;
  } catch {
    return null;
  }
}

const sharedUrl = urlFromHash();
if (sharedUrl) {
  state = newCase();
  state.emailRaw = `Subject: URL submitted from the browser extension\n\n${sharedUrl}\n`;
  state.sourceName = 'browser extension';
  render();
  actions.analyze().then(() => { if (state.analysis) setStage(2); });
} else {
  render();
  if (state.analysis) { scoreUrls(); enrichAll(); }
}
fetch(API_BASE + '/config')
  .then(r => r.json())
  .then(c => {
    config = c;
    // First run: prefer a local LLM if one is running. Never default to the cloud.
    if (state.aiProvider === 'template' && !state.providerChosen
        && c.ai?.ollama?.available) state.aiProvider = 'ollama';
    render();
  })
  .catch(() => { /* backend offline — template AI and analysis will report errors */ });
