# Dataset Sources

You need two classes of URLs: **phishing** (label=1) and **legitimate** (label=0).
Aim for a roughly balanced set — 5,000–10,000 of each is plenty for a final
year project and keeps feature extraction time reasonable.

## Phishing URLs

1. **PhishTank** — https://phishtank.org/developer_info.php
   Free, community-verified phishing URLs. Offers a downloadable CSV of
   currently active/verified phishing pages. Requires free registration
   for the full data feed, but a sample CSV is available without one.

2. **OpenPhish** — https://openphish.com/
   Free tier gives a rolling feed of recently identified phishing URLs
   (no login required for the community feed, updated every few hours).

3. **UCI Machine Learning Repository — Phishing datasets** —
   https://archive.ics.uci.edu/ — search "phishing websites" — several
   pre-labeled, pre-featurized datasets exist here if you want a fallback
   / comparison dataset in addition to your own scraped one.

## Legitimate URLs

1. **Tranco List** — https://tranco-list.eu/
   A research-grade "top sites" ranking (successor to the deprecated Alexa
   Top 1M), designed specifically to be citable in academic work — use
   this over an old Alexa CSV.

2. **Common Crawl** — https://commoncrawl.org/
   If you want more diverse/organic legitimate URLs beyond homepages
   (useful for content-based features), Common Crawl's URL index is a
   good source, though heavier to work with.

## Important notes for your report

- **Timestamp your dataset.** Phishing URLs go dead/get taken down within
  hours to days. Note the exact collection date — this becomes a natural
  "limitations / future work" discussion point (concept drift).
- **Never visit live phishing URLs in a normal browser.** Extract features
  via HTTP requests in a script (or a sandboxed VM) — don't click through
  in your day-to-day browser.
- **Cite your sources properly** in the report (PhishTank, OpenPhish, and
  Tranco all have citable formats on their sites).
- Keep a `data/urls.csv` with two columns: `url,label` — this is the format
  `train_model.py` expects.

---

## v2 training set — `urls_v2.csv` (Phase 4)

Built by `backend/build_dataset.py` (collected October 2026). Columns:
`url,label,source`. It replaces `urls.csv` for training because the original
legitimate class was **mostly bare homepages taken from the same Tranco list
used for the trusted-domain feature** — so the model could learn "has a
path" or "is on the list" instead of what phishing URLs look like.

| source | label | what it is |
|---|---|---|
| `tranco-home` | 0 | down-sampled homepages from the original `urls.csv` |
| `deep-link` | 0 | real deep links from each site's own `sitemap.xml`, for ~2,500 domains sampled across all Tranco rank bands (top 1k … 300k) |
| `cc-platform` | 0 | legitimate pages on free-hosting platforms (github.io, sites.google.com, weebly, wix, vercel, netlify…) from the Common Crawl URL index (CC-MAIN-2026-39), max 6 pages per site |
| `orig-phish` | 1 | phishing rows from the original `urls.csv` |
| `phishdb` | 1 | sample of the Phishing.Database dump (`ALL-phishing-links.tar.gz`, list date 2026-09-25), max 3 URLs per host so one campaign can't dominate |

Any "legitimate" URL that appears in the phishing database is dropped.

Reproduce: `python build_dataset.py collect` (resumable; caches in
`sitemap_cache.jsonl` / `cc_cache.jsonl`, both committed) then
`python build_dataset.py build`.

**Known label noise / limitations** (worth stating in the report):
- Tranco-ranked ≠ guaranteed benign (some ranked sites are spam or piracy).
- Common Crawl returns URLs alphabetically, so platform samples are capped
  per host to stay diverse.
- Phishing feeds are a snapshot; phishing URLs go offline within days, so
  the model should be retrained periodically (concept drift).
