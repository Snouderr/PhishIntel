const $ = id => document.getElementById(id);
const DEFAULT_ORIGINS = ['http://localhost:8000', 'http://127.0.0.1:8000'];

function flash(text, ok = true) {
  $('status').style.color = ok ? '#2e7d32' : '#c62828';
  $('status').textContent = text;
}

function renderAllowlist(list) {
  const ul = $('allowlist');
  if (!list.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = 'No trusted sites yet — add one from the popup with “Always trust this site”.';
    ul.replaceChildren(li);
    return;
  }
  ul.replaceChildren(...list.map(host => {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = host;
    const rm = document.createElement('button');
    rm.textContent = 'Remove';
    rm.addEventListener('click', async () => {
      const { allowlist } = await getSettings();
      const next = allowlist.filter(h => h !== host);
      await chrome.storage.sync.set({ allowlist: next });
      renderAllowlist(next);
      flash(`Removed ${host}`);
    });
    li.append(name, rm);
    return li;
  }));
}

async function load() {
  const s = await getSettings();
  $('apiUrl').value = s.apiUrl;
  for (const k of ['blockHighRisk', 'warnMedium', 'logChecks']) $(k).checked = s[k];
  renderAllowlist(s.allowlist);
}

for (const k of ['blockHighRisk', 'warnMedium', 'logChecks']) {
  $(k).addEventListener('change', async () => {
    await chrome.storage.sync.set({ [k]: $(k).checked });
    flash('Saved');
  });
}

// A non-default API address needs host permission for that origin. The
// extension only asks for it when you set one (it doesn't need <all_urls>).
$('apiUrl').addEventListener('change', async () => {
  let origin;
  try {
    origin = new URL($('apiUrl').value.trim()).origin;
  } catch {
    return flash('Not a valid URL (e.g. http://localhost:8000)', false);
  }
  if (!DEFAULT_ORIGINS.includes(origin)) {
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) return flash(`Permission to reach ${origin} was not granted`, false);
  }
  await chrome.storage.sync.set({ apiUrl: origin });
  $('apiUrl').value = origin;
  flash('Saved');
});

$('test').addEventListener('click', async () => {
  const { apiUrl } = await getSettings();
  $('conn').textContent = 'Testing…';
  try {
    const r = await fetch(`${apiUrl}/health`);
    const h = await r.json();
    $('conn').style.color = h.model_loaded ? '#2e7d32' : '#c62828';
    $('conn').textContent = h.model_loaded
      ? `Connected — model v${h.model_version || '?'} loaded`
      : 'Connected, but the model is not loaded (run train_model.py)';
  } catch {
    $('conn').style.color = '#c62828';
    $('conn').textContent = `Could not reach ${apiUrl} — is the backend running?`;
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && changes.allowlist) renderAllowlist(changes.allowlist.newValue || []);
});

load();
