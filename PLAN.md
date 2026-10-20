# Project Plan — Phishing Detector + PhishIntel

Two projects, one system:

- **phishing-detector**: ML URL classifier (FastAPI) + Chrome extension that warns while browsing.
- **phishintel**: analyst web app that walks a suspicious email through 6 investigation stages
  (sample → headers → URLs → IOCs → infrastructure → report).

End goal: PhishIntel parses a *real* email, scores its URLs with the detector's ML model,
enriches indicators with live threat intel, and produces a real report. Both share one backend.

```
 Chrome extension ──┐
                    ├──► FastAPI backend ──► ML model (/predict)
 PhishIntel web UI ─┘         │           ──► email parser (/analyze/email)
                              │           ──► enrichment: RDAP, DNS, URLhaus, VirusTotal (/enrich/*)
                              └───────────► Claude API proxy (/ai/summarize) — key stays server-side
```

---

## Current state (audit, 2026-10-19)

### phishing-detector — working, but the evaluation is optimistic
- 17 lexical URL features, 4 models compared, Random Forest saved. API + extension run end-to-end.
- **Dataset leakage:** legit URLs (18k) come from Tranco — the *same* list as `trusted_domains.txt`
  — so `is_trusted_domain` is 97.6% for legit vs 67% for phishing. Legit URLs are also nearly all
  bare homepages with HTTPS (100%), so "has a path" / "no HTTPS" act as shortcuts.
- Random train/test split → same domain can appear in both sets (inflates scores).
- 58 duplicate URLs. Imbalance 18k : 10k.
- `@app.on_event("startup")` is deprecated in FastAPI; no tests; no pinned versions.

### phishintel — UI shell, mostly static demo data
- Header results, URL verdicts, IOCs, WHOIS, kill chain, and report are all **hardcoded**.
- **XSS:** pasted email, added URLs and IOCs are inserted into `innerHTML` unescaped; URLs are
  also interpolated into inline `onclick` strings.
- **AI call broken & unsafe:** API key in client JS, missing CORS opt-in header, outdated model ID.
- `exportCSV` drops 2 of the default IOCs; `state.apiKey` unused.

---

## Similar projects reviewed (what we borrow)

| Project | Idea worth taking |
|---|---|
| ThePhish (TheHive/Cortex/MISP) | Extract observables from header + body → enrich each → verdict; export to MISP |
| PhishSage / EmailAnalyzer | Python stdlib `email` parsing; extract URLs, IPs, emails, attachments + hashes |
| PhishHound | Rule-based header verdict (LOW/MED/HIGH) **with reasons** |
| Sublime Security | Detections as readable rules; lookalike / impersonation detection |
| NoPhish, XGBoost-extension papers | WHOIS/domain-age features; XGBoost usually beats RF on URL features |
| Hawk Eyes extension | Hybrid: blocklist + allowlist + heuristics + ML |
| dnstwist / typosquat scanners | Edit distance + homoglyph/punycode checks against a brand list |

---

## Technologies & requirements

| Layer | Tech | Status |
|---|---|---|
| Runtime | Python 3.13 (`.venv` at repo root), Node 22 (tooling only) | installed |
| API | FastAPI 0.141, Uvicorn 0.54, Pydantic 2.13 | installed |
| ML | scikit-learn 1.9, pandas 3.0, numpy 2.5, joblib 1.6 | installed |
| ML (add) | xgboost, shap (explanations) | Phase 4 |
| HTTP / testing (add) | httpx (+ httpx2 for FastAPI TestClient), pytest | Phase 0 |
| Enrichment (add) | dnspython (MX/A/SPF records), RDAP via httpx (domain age, no key) | Phase 2 |
| Config (add) | python-dotenv — keeps API keys in `backend/.env`, never in JS | Phase 2 |
| Optional storage | SQLite (stdlib) — prediction log + saved investigations | Phase 2/5 |
| Frontend | Plain HTML/CSS/JS (no build step), Chrome Manifest V3 | existing |
| External APIs | Anthropic Claude (key), URLhaus/abuse.ch (free key), VirusTotal (free key, 4 req/min), RDAP (no key) | Phase 2 |

---

## Phases

Each phase ends with something runnable and testable. Tick boxes as we go.

### Phase 0 — Foundation & hygiene
- [x] `.gitignore` (venv, `__pycache__`, `.env`, large data archives)
- [x] First commit
- [x] Pin `requirements.txt`; add `httpx2` (TestClient), `pytest`, `python-dotenv`
- [x] Replace deprecated `on_event` with FastAPI `lifespan`; missing model now returns 503 not 500
- [x] Tests: `tests/test_features.py`, `tests/test_api.py` — 19 passing
      (run: `cd phishing-detector/backend && ../../.venv/Scripts/python -m pytest`)
- [x] Serve PhishIntel from the backend (`/app` static mount; `/` redirects there)

### Phase 1 — PhishIntel: safe, data-driven frontend ✅
- [x] `esc()` helper for all user data in templates; replace inline `onclick` strings with
      event delegation (`data-action` attributes) — verified an injected `<img onerror>` doesn't fire
- [x] Accept pasted email **or** `.eml` file upload (drag & drop)
- [x] Stage 2 shows the **parsed** headers: SPF/DKIM/DMARC, From vs
      Reply-To vs Return-Path mismatch, display-name spoofing, Received hop chain with IPs
- [x] Stage 3 lists URLs actually found in the body (plain text + HTML `href` + `<form action>`,
      defanged forms refanged), link-text vs real-href mismatch, attachments with hashes,
      **ML score per URL from `/predict`** (pulled forward from Phase 3)
- [x] Stage 4 IOCs auto-generated from parsed data + manual add/remove/restore; dedupe
- [x] Stage 5 attack chain built from the analysis (enrichment still Phase 2–3)
- [x] Stage 6 report + recommendations built from findings; exports: CSV, JSON, Markdown;
      defang toggle
- [x] Persist the investigation in `localStorage` so refresh doesn't lose work
- [x] Demo samples as real `.eml` files in `phishintel/samples/` (DocuSign, Microsoft 365,
      bank KYC + attachment, legitimate GitHub email) — also used by the tests
- [x] Pulled forward from Phase 2: `POST /analyze/email` (`backend/email_analysis.py`) —
      MIME parsing needs Python's `email` package, so the frontend calls it from the start
- [x] Fix: URL shorteners no longer get the trusted-domain override in `/predict`

### Phase 2 — Backend: analysis & enrichment endpoints ✅ (keyless by default)
- [x] `POST /analyze/email` — done in Phase 1
- [ ] Scan HTML attachments for forms/links (e.g. the bank sample's `KYC_Form.pdf.html`) — moved to Phase 3
- [x] `POST /enrich/domain` — RDAP (rdap.org) domain age/registrar + DNS A/MX/NS/SPF/DMARC (dnspython)
- [x] `POST /enrich/ip` — ASN, owner, country via Team Cymru DNS + reverse DNS (no key)
- [x] `POST /enrich/url` — ML score + local phishing DB (Phishing.Database dump → SQLite,
      784k URLs / 497k hosts, shared platforms like sites.google.com excluded from host hits)
      + OpenPhish community feed; URLhaus / VirusTotal only if keys set
- [x] `POST /ai/summarize` — providers: **built-in template (offline, default)**, **Ollama (local)**,
      **Gemini (cloud, opt-in)**. Only derived facts are sent, never the email body;
      redaction on by default; `dry_run` returns the exact prompt → UI preview + confirm before
      anything goes to Gemini
- [x] `GET /config` — which providers / intel sources are available
- [x] In-memory TTL cache (6 h) for lookups; failures returned as `{error}` instead of raising
- [x] Tests with mocked external calls — 67 passing
- [x] Frontend: AI engine picker, Gemini preview/confirm, blocklist column (Stage 3),
      live infrastructure intel (Stage 5), intel findings feed the verdict + report

### Phase 3 — Deeper analysis & polish
- [x] Stage 2 ← `/analyze/email`; Stage 3 ← `/enrich/url`; Stage 5 ← `/enrich/domain` + `/enrich/ip` (done in Phases 1–2)
- [x] Overall risk score combining email findings + intel (domain age, blocklists) (done in Phase 2)
- [x] AI buttons call `/ai/summarize` (done in Phase 2)
- [ ] Scan HTML attachments for forms/links; QR-code images in emails (quishing)
- [ ] Map findings to MITRE ATT&CK (T1566.001/.002 phishing, T1598, T1656 impersonation)
- [ ] Show *why* each verdict point was added (score breakdown) in the report
- [ ] Optional: Certificate Transparency (crt.sh) first-seen date as a second age signal

### Phase 4 — ML model improvements ✅ (see `phishing-detector/README.md` for results)
- [x] Rebuild dataset (`build_dataset.py` → `data/urls_v2.csv`, 28,868 URLs): real deep links
      from sitemaps of ~2,500 Tranco domains across all rank bands, legit pages on 16 hosting
      platforms (Common Crawl), phishing capped per host; collection date recorded
- [x] Remove leakage: `is_trusted_domain` / `is_restricted_tld` out of the model, rule layer only
- [x] Split by **domain** (shared platforms split by host); 5-fold `StratifiedGroupKFold` for selection
- [x] New features (17): punycode, brand in subdomain/path, brand edit distance + typosquat,
      free hosting, abused TLD, path depth, file extension, embedded URL, entropy, token length…
      (domain age deliberately left out — it needs a network call per URL; PhishIntel uses it instead)
- [x] Models: LR / Random Forest / HistGradientBoosting (sklearn's gradient boosting — same
      family as XGBoost, no extra dependency); sigmoid calibration; threshold from CV
      predictions at precision ≥ 97%
- [x] `reports/`: metrics.json, ROC/PR curves vs v1, confusion matrix, permutation importance,
      false positive / negative lists
- [x] `/predict` returns up to 3 **reasons** (occlusion in log-odds, `explain.py`) + model version;
      PhishIntel shows them under each URL
- [x] Hybrid rules: brand-impersonation floor, shortener → medium, trust cap (now excludes
      shorteners); risk bands anchored on the model's threshold
- [x] Result: unseen-URL false-positive rate 75% (v1) → 6.3% (v2); held-out test F1 0.955,
      FPR 3.6%. v1 kept in `backend/legacy_v1/` for the comparison

### Phase 5 — Extension upgrades
- [ ] Popup shows the reasons from `/predict`
- [ ] "Report false positive" + per-user allowlist (`chrome.storage`)
- [ ] Full-page interstitial for high risk (with "proceed anyway")
- [ ] Settings page: API URL, sensitivity threshold
- [ ] Log predictions to SQLite via API (for FP/FN review)
- [ ] "Investigate in PhishIntel" button → opens app with the URL pre-loaded
- [ ] Tighten `host_permissions`; check punycode lookalikes client-side

### Phase 6 — Documentation & delivery
- [ ] Top-level README: architecture diagram, setup, `.env.example`, run commands
- [ ] Evaluation write-up (metrics before/after leakage fix — good report material)
- [ ] Limitations: concept drift, WHOIS privacy, API rate limits, lexical-only blind spots
- [ ] Optional: Dockerfile / `docker compose up` for one-command demo

---

## Order of work
0 → 1 → 2 → 3 gives a working, real PhishIntel quickly. Phase 4 (ML) is independent and can
run in parallel once Phase 0 tests exist. Phases 5–6 last.
