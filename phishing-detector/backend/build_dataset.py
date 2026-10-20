"""
Builds data/urls_v2.csv — a less biased training set than the original
urls.csv, whose legitimate class was mostly bare homepages taken from the
same Tranco list used for the trusted-domain feature.

Legitimate (label 0), no API keys needed:
  * real deep links (paths + queries) from each site's own sitemap.xml, for
    ~2,000 domains sampled across the whole Tranco top-300k ranking, not
    just the top sites
  * legitimate pages on free-hosting / UGC platforms (github.io,
    sites.google.com, weebly, pages.dev…) from the Common Crawl URL index —
    the places phishing hides, so the model must learn the page, not the
    platform
  * the existing homepage rows, down-sampled
  Any URL that appears in the local phishing database is dropped.

Phishing (label 1):
  * the existing phishing rows + a sample of the Phishing.Database dump,
    capped per host so one kit/campaign can't dominate

Usage:
    python build_dataset.py collect   # resumable (data/sitemap_cache.jsonl, cc_cache.jsonl)
    python build_dataset.py build     # writes data/urls_v2.csv
"""

import gzip
import html
import json
import os
import random
import re
import sqlite3
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
import pandas as pd

import intel
from feature_extraction import get_full_domain

DATA = intel.DATA_DIR
CC_INDEX = "https://index.commoncrawl.org/CC-MAIN-2026-39-index"
CC_CACHE = os.path.join(DATA, "cc_cache.jsonl")
SITEMAP_CACHE = os.path.join(DATA, "sitemap_cache.jsonl")
OUT = os.path.join(DATA, "urls_v2.csv")
TRUSTED = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")

N_DOMAINS = 2500
PER_DOMAIN = 6
UGC_PLATFORMS = [
    "github.io", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com",
    "netlify.app", "vercel.app", "pages.dev", "firebaseapp.com", "web.app",
    "sites.google.com", "notion.site", "gitlab.io", "webflow.io", "herokuapp.com",
    "glitch.me", "square.site", "carrd.co",
]
PER_PLATFORM = 400
PHISH_SAMPLE = 5000
PHISH_PER_HOST = 3
SEED = 42


# ─── Common Crawl collection ─────────────────────────────────────────────

def _cc_query(params: dict) -> list[str]:
    base = {"output": "json", "fl": "url", "filter": ["status:200", "mime:text/html"]}
    for attempt in range(4):
        try:
            r = httpx.get(CC_INDEX, params={**base, **params}, timeout=60,
                          headers={"User-Agent": "PhishIntel-research/1.0 (student project)"})
            if r.status_code == 404:  # no captures
                return []
            if r.status_code in (429, 503, 504):  # Common Crawl's "slow down"
                time.sleep(15 * 2 ** attempt)
                continue
            r.raise_for_status()
            return [json.loads(line)["url"] for line in r.text.splitlines() if line.strip()]
        except (httpx.HTTPError, ValueError):
            time.sleep(10)
    return None  # failed — retried on the next run


def _pick_deep_links(urls: list[str], k: int, rng) -> list[str]:
    """Prefer URLs with a real path; dedupe by path."""
    seen, deep = set(), []
    for u in urls:
        p = urlparse(u)
        key = (p.hostname, p.path)
        if key in seen or len(u) > 300:
            continue
        seen.add(key)
        if p.path not in ("", "/"):
            deep.append(u)
    rng.shuffle(deep)
    return deep[:k]


def _load_done(path) -> set:
    done = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                done.add(json.loads(line)["key"])
    return done


def collect_platforms():
    """Legit pages on free-hosting platforms, from Common Crawl — one request
    at a time: the free index answers 503 'slow down' to parallel clients."""
    rng = random.Random(SEED)
    done = _load_done(CC_CACHE)
    jobs = [p for p in UGC_PLATFORMS if "platform:" + p not in done]
    print(f"Common Crawl: {len(jobs)} platforms to fetch")
    with open(CC_CACHE, "a", encoding="utf-8") as out:
        for p in jobs:
            urls = _cc_query({"url": p, "matchType": "domain", "limit": 3000})
            if urls is not None:
                out.write(json.dumps({"key": "platform:" + p,
                                      "urls": _pick_deep_links(urls, PER_PLATFORM, rng)}) + "\n")
                out.flush()
            print(f"  {p}: {'failed' if urls is None else len(urls)}", flush=True)
            time.sleep(3)


_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
MAX_SITEMAP_BYTES = 8_000_000


def _get_text(client, url):
    with client.stream("GET", url) as r:
        if r.status_code != 200:
            return None
        body = b""
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_SITEMAP_BYTES:
                break
    if url.endswith(".gz") or body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)
        except (OSError, EOFError):
            return None
    return body.decode("utf-8", "ignore")


def _sitemap_urls(domain: str) -> list[str]:
    """Deep links a site publishes for crawlers: robots.txt -> Sitemap:, else
    /sitemap.xml; follows one level of sitemap index."""
    try:
        with httpx.Client(timeout=10, follow_redirects=True, headers={
                "User-Agent": "PhishIntel-research/1.0 (student project; reads sitemaps only)"}) as c:
            robots = _get_text(c, f"https://{domain}/robots.txt") or ""
            maps = [l.split(":", 1)[1].strip() for l in robots.splitlines()
                    if l.lower().startswith("sitemap:")][:3]
            maps = maps or [f"https://{domain}/sitemap.xml", f"https://www.{domain}/sitemap.xml",
                            f"https://{domain}/sitemap_index.xml"]
            for sm in maps:
                text = _get_text(c, sm)
                if not text:
                    continue
                locs = _LOC_RE.findall(text)
                if "<sitemapindex" in text[:2000].lower() and locs:
                    locs = _LOC_RE.findall(_get_text(c, locs[0]) or "")
                locs = [html.unescape(u) for u in locs
                        if not u.lower().endswith((".xml", ".gz", ".jpg", ".png", ".pdf"))]
                if locs:
                    return locs[:5000]
            return []
    except (httpx.HTTPError, UnicodeError, ValueError):
        return []


def collect_sitemaps():
    rng = random.Random(SEED)
    done = _load_done(SITEMAP_CACHE)
    with open(TRUSTED, encoding="utf-8") as f:
        ranked = [d.strip() for d in f if d.strip()]
    # Stratified across rank bands so the model sees ordinary sites, not just giants
    bands = [(0, 1000), (1000, 10000), (10000, 50000), (50000, 150000), (150000, len(ranked))]
    domains = []
    for lo, hi in bands:
        domains += rng.sample(ranked[lo:hi], min(N_DOMAINS // len(bands), hi - lo))
    jobs = [d for d in domains if "sitemap:" + d not in done]
    print(f"Sitemaps: {len(done)} cached, {len(jobs)} to fetch")
    ok = 0
    with open(SITEMAP_CACHE, "a", encoding="utf-8") as out, ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_sitemap_urls, d): d for d in jobs}
        for i, fut in enumerate(as_completed(futures), 1):
            d = futures[fut]
            urls = _pick_deep_links(fut.result() or [], PER_DOMAIN, rng)
            ok += bool(urls)
            out.write(json.dumps({"key": "sitemap:" + d, "urls": urls}) + "\n")
            out.flush()
            if i % 100 == 0 or i == len(jobs):
                print(f"  {i}/{len(jobs)}  with deep links: {ok}", flush=True)


def collect():
    collect_sitemaps()
    collect_platforms()


# ─── Build the CSV ───────────────────────────────────────────────────────

def _host(url: str) -> str:
    return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()


def _phishing_sample(rng, exclude: set) -> list[str]:
    with tarfile.open(intel.LINKS_ARCHIVE, "r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.isfile())
        lines = [l.decode("utf-8", "ignore").strip() for l in tar.extractfile(member)]
    lines = [l for l in lines if l.startswith(("http://", "https://")) and len(l) < 400]
    rng.shuffle(lines)
    per_host, out = {}, []
    for u in lines:
        h = _host(u)
        if not h or u in exclude or per_host.get(h, 0) >= PHISH_PER_HOST:
            continue
        per_host[h] = per_host.get(h, 0) + 1
        out.append(u)
        if len(out) >= PHISH_SAMPLE:
            break
    return out


def build():
    rng = random.Random(SEED)
    old = pd.read_csv(os.path.join(DATA, "urls.csv")).drop_duplicates("url")

    cc_urls = []
    for path in (CC_CACHE, SITEMAP_CACHE):
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                src = "cc-platform" if rec["key"].startswith("platform:") else "deep-link"
                cc_urls += [(u, src) for u in rec["urls"]]

    # Drop any "legit" URL that is actually on the phishing list
    con = sqlite3.connect(intel.BLOCKLIST_DB)
    def listed(u):
        return con.execute("SELECT 1 FROM urls WHERE u=?", (intel.normalize_url(u),)).fetchone() is not None
    # Common Crawl lists URLs alphabetically, so one site can fill a whole
    # platform's quota — cap pages per host to keep the set diverse.
    per_host, capped = {}, []
    for u, s in cc_urls:
        h = _host(u)
        if per_host.get(h, 0) < PER_DOMAIN:
            per_host[h] = per_host.get(h, 0) + 1
            capped.append((u, s))
    cc_urls = capped
    legit_cc = [(u, s) for u, s in cc_urls if not listed(u)]
    print(f"Common Crawl legit: {len(legit_cc)} (dropped {len(cc_urls) - len(legit_cc)} blocklisted)")

    old_legit = old[old.label == 0].sample(n=min(7000, (old.label == 0).sum()), random_state=SEED)
    old_phish = old[old.label == 1]
    new_phish = _phishing_sample(rng, set(old.url))

    rows = ([(u, 0, "tranco-home") for u in old_legit.url] +
            [(u, 0, s) for u, s in legit_cc] +
            [(u, 1, "orig-phish") for u in old_phish.url] +
            [(u, 1, "phishdb") for u in new_phish])
    df = pd.DataFrame(rows, columns=["url", "label", "source"]).drop_duplicates("url")
    # A URL can't be both — keep the phishing label if it shows up twice
    df = df.sort_values("label", ascending=False).drop_duplicates("url").sample(frac=1, random_state=SEED)
    df.to_csv(OUT, index=False)
    print(df.groupby(["label", "source"]).size().to_string())
    print(f"Wrote {len(df)} rows to {OUT}")


if __name__ == "__main__":
    {"collect": collect, "build": build}[sys.argv[1] if len(sys.argv) > 1 else "collect"]()
