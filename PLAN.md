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
- [ ] First commit (waiting on your go-ahead)
- [x] Pin `requirements.txt`; add `httpx2` (TestClient), `pytest`, `python-dotenv`
- [x] Replace deprecated `on_event` with FastAPI `lifespan`; missing model now returns 503 not 500
- [x] Tests: `tests/test_features.py`, `tests/test_api.py` — 19 passing
      (run: `cd phishing-detector/backend && ../../.venv/Scripts/python -m pytest`)
- [x] Serve PhishIntel from the backend (`/app` static mount; `/` redirects there)

### Phase 1 — PhishIntel: safe, data-driven frontend
- [ ] `esc()` helper for all user data in templates; replace inline `onclick` strings with
      event delegation (`data-action` attributes)
- [ ] Accept pasted email **or** `.eml` file upload (drag & drop)
- [ ] Stage 2 shows the **parsed** headers (from Phase 2 endpoint): SPF/DKIM/DMARC, From vs
      Reply-To vs Return-Path mismatch, display-name spoofing, Received hop chain with IPs
- [ ] Stage 3 lists URLs actually found in the body (plain text + HTML `href`, defanged forms
      like `hxxp://` / `[.]` refanged), shows link-text vs real-href mismatch
- [ ] Stage 4 IOCs auto-generated from parsed data + manual add/remove; dedupe
- [ ] Stage 6 report built from state (not a fixed string); exports: CSV, JSON, Markdown;
      defanged indicators in exports
- [ ] Persist the investigation in `localStorage` so refresh doesn't lose work
- [ ] Keep "Load demo sample" (several samples: DocuSign, Microsoft 365, bank OTP)

### Phase 2 — Backend: analysis & enrichment endpoints
- [ ] `POST /analyze/email` — Python `email` package: headers, auth results, Received chain,
      URLs, IPs, emails, attachments (name, type, SHA-256), rule-based verdict **with reasons**
- [ ] `POST /enrich/domain` — RDAP registration date → domain age; DNS A/MX/TXT(SPF) via dnspython
- [ ] `POST /enrich/url` — URLhaus lookup; VirusTotal if key configured; ML score via `/predict` logic
- [ ] `POST /ai/summarize` — Claude proxy; key from `.env`; stage-specific prompts; current model ID
- [ ] Caching (in-memory TTL) + rate limits for external lookups; graceful "not configured" responses
- [ ] Tests with mocked external calls

### Phase 3 — Wire PhishIntel to the backend
- [ ] Stage 2 ← `/analyze/email`; Stage 3 ← `/predict` + `/enrich/url` (real ML % + intel hits)
- [ ] Stage 5 ← `/enrich/domain` (real domain age, registrar, DNS, IP/ASN); kill chain built from data
- [ ] Map findings to MITRE ATT&CK (T1566.001/.002 phishing, T1598, T1656 impersonation)
- [ ] Overall risk score combining header, URL-ML, intel and age signals, with explanation
- [ ] AI buttons call `/ai/summarize`

### Phase 4 — ML model improvements (the "research" part of the project)
- [ ] Rebuild dataset: dedupe; legit URLs **with real paths** (Common Crawl / crawled Tranco pages,
      not just homepages); balance classes; record collection date
- [ ] Remove leakage: move `is_trusted_domain` out of the model into the rule layer only;
      check `uses_https` and path features after rebalancing
- [ ] Split by **domain** (`GroupShuffleSplit`) so no domain is in both train and test
- [ ] New features: punycode/IDN, brand name in subdomain/path, edit distance to top brands
      (typosquatting), TLD risk, path token stats, consonant/vowel ratio, URL entropy,
      optional domain age (cached RDAP)
- [ ] Add XGBoost; 5-fold CV; `GridSearchCV`; probability calibration; choose threshold for recall
- [ ] Evaluation outputs: confusion matrix, ROC/PR curves, feature importance → `reports/`
- [ ] `/predict` returns **top reasons** for each verdict (SHAP or feature contributions)

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
