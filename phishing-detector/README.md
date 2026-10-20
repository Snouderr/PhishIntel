# Phishing Detector + PhishIntel

A final-year project with two parts sharing one FastAPI backend:

- **Phishing URL detector**: an ML model that scores any URL, served to a
  Chrome extension that warns you while browsing.
- **PhishIntel** (`../phishintel/`): a web app for investigating a suspicious
  email in 6 stages (sample → headers → URLs → IOCs → infrastructure →
  report). It parses the real email, scores every link with the model,
  enriches domains/IPs with free threat intel, and exports a report.

```
 Chrome extension ──┐
                    ├──► FastAPI backend ──► ML URL model + rules   POST /predict
 PhishIntel web UI ─┘    (backend/api.py) ──► email parser          POST /analyze/email
                                          ──► RDAP · DNS · ASN · blocklists   POST /enrich/*
                                          ──► AI summaries (built-in / Ollama / Gemini)   POST /ai/summarize
```

## Quick start (Windows)

```bash
# from the repo root — one virtual environment for everything
python -m venv .venv
.venv\Scripts\activate
pip install -r phishing-detector/backend/requirements.txt

cd phishing-detector/backend
uvicorn api:app --port 8000
```

- PhishIntel: **http://localhost:8000/app/** (load a demo sample, click Analyze)
- API docs: http://localhost:8000/docs
- Extension: `chrome://extensions` → Developer mode → *Load unpacked* → `phishing-detector/extension/`
- Tests: `cd phishing-detector/backend && python -m pytest` (80 tests, no network needed)

Optional keys go in `backend/.env` (copy `.env.example`). **Everything works
without any key.** Gemini enables cloud AI summaries; VirusTotal and URLhaus
add extra lookups. Ollama (local LLM) is detected automatically when it's running.

## The URL model (v2)

`backend/train_model.py` trains on `data/urls_v2.csv` (28,868 URLs, built by
`backend/build_dataset.py`; see `data/DATASETS.md`).

**Why v2 exists:** the original model reported F1 0.995, but the evaluation
was flawed:
1. **Label leakage:** the legitimate URLs came from the Tranco list, the same
   list behind the `is_trusted_domain` feature.
2. **Shortcut learning:** 67% of legitimate URLs were bare homepages, so
   "has a path" alone looked like phishing.
3. **Random train/test split:** the same domain appeared in both sets.

v2 fixes all three:
- **No leaked features:** list-membership features are kept out of the model
  and live only in the API's rule layer.
- **Realistic legitimate URLs:** real deep links from site sitemaps, plus
  legitimate pages on free-hosting platforms.
- **Domain-grouped splits:** every split is grouped by domain, so test
  domains are never seen in training.
- **Stricter model building:** model selection uses 5-fold group CV,
  probabilities are calibrated, and the decision threshold keeps precision
  at or above 97%.

| Held-out test set (5,731 URLs, domains unseen in training) | v2 |
|---|---|
| Precision / Recall / F1 | 0.964 / 0.946 / **0.955** |
| ROC-AUC / PR-AUC | 0.990 / 0.991 |
| False-positive rate | **3.6%** |

| Test URLs neither model trained on (2,441) | v1 (old) | v2 |
|---|---|---|
| F1 | 0.641 | **0.933** |
| False-positive rate | **75.3%** | **6.3%** |
| Legit pages on hosting platforms, accuracy | 0% | 96.8% |
| Legit deep links, accuracy | 34% | 92.5% |

The old model flagged three out of four ordinary legitimate pages as phishing.
Its 0.995 came entirely from the test set looking like its training set.

Models compared by 5-fold group CV: Random Forest (F1 0.946, selected),
Histogram Gradient Boosting (0.945), Logistic Regression (0.890). Figures and
error lists are in `reports/`:
- `roc_pr_curves.png`, `confusion_matrix.png`, `feature_importance.png`
- `errors_false_positives.csv` / `errors_false_negatives.csv`
- `metrics.json` (every number above)

The v1 model is kept in `backend/legacy_v1/` so every retrain re-runs the
comparison.

**Features (33, all from the URL text, no network):**
- *Structure:* length, dots, hyphens, digits, entropy, subdomains, path
  depth, file extension, embedded URL, query length.
- *Lookalikes:* brand typo distance (e.g. `paypa1`, `steamcommunlty`), brand
  name used in a subdomain or path, punycode.
- *Hosting:* free-hosting platform, abused TLD, URL shortener / QR redirector.

**Rules on top of the model (hybrid design):**
- *Trusted-domain cap:* popular domains (Tranco) and restricted Indian
  suffixes (`bank.in`, `gov.in`…) are capped at 5%. Free-hosting platforms
  and shorteners are excluded from the cap.
- *Brand-impersonation floor:* typosquats, a brand used as a subdomain, or a
  brand name on someone else's domain are raised to at least "high".
- *Shortener handling:* shortened / QR links are reported as "medium",
  because their text can't show where they lead.

**Explanations:** `/predict` returns up to 3 reasons per verdict
(`backend/explain.py`). Each feature is reset to the typical legitimate value
and the change in log-odds is measured. Example:
`paypa1-secure.com/login.php` → *"Domain uses a brand name it doesn't belong
to"*, *"Points directly at a script/page file"*, *"Not using HTTPS"*.

Retrain: `python build_dataset.py build && python train_model.py` (≈4 min).

## Limitations (for the report)

- **URL-only:** phishing hosted on legitimate services (QR landing pages,
  form builders, `linkedin.com/slink` redirects) has an innocent-looking URL,
  and most missed phishing is of this kind. The email analysis and blocklists
  in PhishIntel cover part of this gap.
- **Random-looking IDs:** URLs with long random IDs or UUIDs
  (`/questions/4hvdw1gbyzx2rt`) cause most false alarms.
- **Concept drift:** phishing feeds are a snapshot (list date 2026-09-25), so
  the model should be retrained periodically.
- **Label noise:** Tranco rank does not guarantee a site is benign.
