"""
URL feature extraction for phishing detection.
 
Extracts lexical/structural features directly from a URL string, without
needing to fetch the page — fast, safe, and works even if the site is down.
 
TODOs mark where you can add content-based features (require an HTTP
request to fetch the page HTML) and WHOIS-based features (domain age).
Both are good "extend the baseline" additions for your report.
"""
 
import re
import math
import os
from urllib.parse import urlparse

from brands import (ALL_BRAND_DOMAINS, BRAND_DOMAINS, FREE_HOSTING_PLATFORMS, LEET,
                    SUSPICIOUS_TLDS, brand_matches, levenshtein)
 
_TRUSTED_DOMAINS_PATH = os.path.join(
    os.path.dirname(__file__), "trusted_domains.txt"
)
_trusted_domains_cache = None
 
 
def _load_trusted_domains() -> set:
    """
    Lazily loads the trusted-domain whitelist (Tranco top 300k) once per
    process. Returns an empty set (feature degrades to 0 for everything)
    if the file isn't present, so the extractor never crashes without it.
    """
    global _trusted_domains_cache
    if _trusted_domains_cache is None:
        try:
            with open(_TRUSTED_DOMAINS_PATH, encoding="utf-8") as f:
                _trusted_domains_cache = {
                    line.strip().lower() for line in f if line.strip()
                }
        except FileNotFoundError:
            _trusted_domains_cache = set()
    return _trusted_domains_cache
 
# Common multi-part public suffixes we want to treat as one "suffix" unit
# so e.g. "example.co.uk" doesn't get its domain misread as "co".
# Not exhaustive (a full list is the public suffix list, psl) but covers
# the common cases well enough for a lexical-feature baseline.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "com.br", "co.za",
    # Indian sector-specific second-levels: shared categories many
    # different, unrelated organizations register under (e.g.
    # icici.bank.in and hdfc.bank.in are different banks, not
    # subdomains of one "bank.in" site) — must be treated as suffixes,
    # not apex domains, or a reputation check on the apex would wrongly
    # extend trust across every organization sharing the category.
    "bank.in", "gov.in", "nic.in", "res.in", "ac.in",
}
 
# Subset of the above that require verified eligibility to register at
# all (confirmed via NIXI/INRegistry policy), as opposed to "co.in",
# "net.in", "org.in" etc. which have been open to anyone since 2005.
# A domain under one of these is structurally hard to spoof regardless
# of whether it's globally popular enough to appear on a traffic-based
# whitelist like Tranco — bank.in requires an RBI banking license
# (registrar: IDRBT), gov.in/nic.in are government-only (registrar:
# NIC), and ac.in/res.in are restricted to accredited academic/research
# institutions (registrar: ERNET).
RESTRICTED_ELIGIBILITY_SUFFIXES = {"bank.in", "gov.in", "nic.in", "ac.in", "res.in"}
 
 
def _split_domain(hostname: str):
    """
    Lightweight stand-in for tldextract: splits a hostname into
    (subdomain, domain, suffix) without needing the external package
    or network access to fetch the public suffix list.
    """
    if not hostname:
        return "", "", ""
 
    parts = hostname.lower().split(".")
    if len(parts) < 2:
        return "", parts[0] if parts else "", ""
 
    # Check for a known multi-part suffix (e.g. co.uk) first
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_SUFFIXES and len(parts) >= 3:
        suffix = last_two
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
    else:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
 
    return subdomain, domain, suffix
 
SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "banking",
    "confirm", "signin", "webscr", "ebayisapi", "paypal", "password",
]
 
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "tiny.cc",
    "s.id", "v.gd", "shorturl.com", "bl.ink", "short.io", "lnkd.in",
    # QR-code generator redirectors — heavily used in "quishing" campaigns
    "qrco.de", "q-r.to", "ead.me", "me-qr.com", "qr.link", "qrfy.io",
}

# Columns extract_features() returns that must NOT go into the model:
#  * is_trusted_domain — legit training URLs come from the same Tranco list,
#    so the model would learn "on the list = safe" (label leakage);
#  * is_restricted_tld — a policy rule (bank.in, gov.in), applied in api.py.
# Both are still computed: the API uses them for the trust override.
NON_MODEL_FEATURES = {"is_trusted_domain", "is_restricted_tld"}
 
 
def _count_meaningful_subdomains(subdomain: str) -> int:
    """
    Count subdomain parts, excluding a leading 'www'.
    'www' is present on a huge fraction of legitimate sites and carries
    essentially no phishing signal on its own, but naive datasets (e.g.
    top-domain lists that store only apex domains like 'wikipedia.org')
    never include it — so a model trained on num_subdomains without this
    adjustment learns 'has any subdomain' as a false phishing signal and
    flags ordinary www.example.com pages. Genuinely unusual subdomains
    (e.g. 'login.verify.example.com') still count normally.
    """
    if not subdomain:
        return 0
    parts = [p for p in subdomain.split(".") if p]
    if parts and parts[0] == "www":
        parts = parts[1:]
    return len(parts)
 
 
def _shannon_entropy(s: str) -> float:
    """Higher entropy can indicate randomly-generated/obfuscated domains."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)
 
 
_FILE_EXT_RE = re.compile(r"\.(php|html?|aspx?|jsp|cgi|js)$", re.I)
_TOKEN_SPLIT_RE = re.compile(r"[/\-._?=&%+~:#@]+")
# Brand names plus the labels of their real domains (steamcommunity,
# microsoftonline); short ones are left out — at 4 letters almost any word
# is within edit distance 1-2.
_BRAND_TARGETS = sorted({b for b in BRAND_DOMAINS if len(b) >= 5} |
                        {d.split(".")[0] for d in ALL_BRAND_DOMAINS if len(d.split(".")[0]) >= 5})


def _min_brand_distance(label: str) -> tuple[int, int]:
    """
    Smallest edit distance from the registered label — or any hyphen-
    separated part of it — to a brand (digit swaps like 0->o undone first),
    plus the length of the brand it matched.
    0 = brand name used on a domain the brand doesn't own (paypal-secure);
    1-2 = typosquat (paypa1 -> 0 after leet, amazom, steamcommunlty);
    capped at 4 = unrelated.
    """
    norm = label.translate(LEET)
    parts = {norm} | {p for p in norm.split("-") if len(p) >= 4}
    best, best_len = 4, 0
    for part in parts:
        for target in _BRAND_TARGETS:
            d = levenshtein(part, target, max_dist=3)
            if d < best:
                best, best_len = d, len(target)
                if d == 0:
                    return 0, best_len
    return best, best_len


def _v2_features(url, parsed, subdomain, domain, suffix, path, query) -> dict:
    """
    Second-generation features (Phase 4). All lexical — no network — and
    chosen to describe *how the URL is built* rather than which list the
    domain is on, so the model generalises to brand-new domains.
    """
    host = (parsed.hostname or "").lower()
    registered = f"{domain}.{suffix}" if suffix else domain
    on_brand_domain = registered in ALL_BRAND_DOMAINS
    sub_norm = subdomain.translate(LEET)
    sub_tokens = set(_TOKEN_SPLIT_RE.split(sub_norm))
    path_q = (path + "?" + query).lower() if query else path.lower()
    path_tokens = set(_TOKEN_SPLIT_RE.split(path_q))
    segments = [s for s in path.split("/") if s]
    tokens = [t for t in _TOKEN_SPLIT_RE.split(host + path) if t]
    vowels = sum(c in "aeiou" for c in domain)
    letters = sum(c.isalpha() for c in domain)
    brand_dist, brand_len = (4, 0) if on_brand_domain else _min_brand_distance(domain)
    after_scheme = url.split("://", 1)[-1]

    return {
        # Lookalikes
        "is_punycode": int("xn--" in host),
        "brand_in_subdomain": int(not on_brand_domain and any(
            brand_matches(b, sub_norm, sub_tokens) for b in BRAND_DOMAINS)),
        "brand_in_path": int(not on_brand_domain and any(
            brand_matches(b, path_q, path_tokens) for b in BRAND_DOMAINS)),
        "brand_edit_distance": brand_dist,
        # 1 edit from any brand, or 2 edits from a long one (2 edits turns
        # "apple" into "applied" — too loose for short names)
        "is_typosquat": int(brand_dist == 1 or (brand_dist == 2 and brand_len >= 8)),
        # Hosting / TLD
        "is_free_hosting": int(registered in FREE_HOSTING_PLATFORMS
                               or host.endswith(".sites.google.com") or host == "sites.google.com"),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        # "www." excluded, like num_subdomains — otherwise "has www" becomes a
        # dataset shortcut (legit URLs carry it far more often than phishing)
        "subdomain_length": len(subdomain.removeprefix("www").lstrip(".")),
        "domain_hyphens": domain.count("-"),
        "domain_digits": sum(c.isdigit() for c in domain),
        "domain_vowel_ratio": round(vowels / letters, 3) if letters else 0,
        # Path / query structure
        "path_depth": len(segments),
        "has_file_extension": int(bool(_FILE_EXT_RE.search(path))),
        "query_length": len(query),
        "has_embedded_url": int("http" in after_scheme.lower() or "//" in after_scheme),
        "longest_token": max((len(t) for t in tokens), default=0),
        "url_entropy": round(_shannon_entropy(url), 3),
    }


def get_full_domain(url: str) -> str:
    """
    Public helper: returns just the apex domain (e.g. 'github.io') for a
    URL. Used by api.py for the UGC-platform check — kept separate from
    extract_features() because that function's output feeds directly into
    the model as numeric columns, and a domain string can't go there.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    _, domain, suffix = _split_domain(parsed.hostname or "")
    return f"{domain}.{suffix}".lower() if suffix else domain.lower()
 
 
def extract_features(url: str) -> dict:
    """
    Extract a feature dict from a single URL.
    Returns a dict of feature_name -> numeric value so it's easy to inspect,
    log, and convert to a DataFrame row.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    subdomain, domain, suffix = _split_domain(parsed.hostname or "")
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parsed.hostname or ""):
        # An IP has no subdomain/domain/TLD structure — without this,
        # 192.168.1.1 reads as "2 subdomains of 1.1"
        subdomain, domain, suffix = "", parsed.hostname, ""
    full_domain = f"{domain}.{suffix}" if suffix else domain
    path = parsed.path or ""
    if path == "/":
        path = ""  # root slash is meaningless noise, not a real path
    query = parsed.query or ""
 
    features = {
        # --- Length-based ---
        "url_length": len(url),
        "domain_length": len(full_domain),
        "path_length": len(path),
 
        # --- Character/structure based ---
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_at_symbols": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": _count_meaningful_subdomains(subdomain),
        "has_ip_address": 1 if re.match(
            r"^(\d{1,3}\.){3}\d{1,3}$", parsed.hostname or ""
        ) else 0,
 
        # --- Protocol / security signals ---
        "uses_https": 1 if parsed.scheme == "https" else 0,
 
        # --- Suspicious content signals ---
        "has_suspicious_word": 1 if any(
            w in url.lower() for w in SUSPICIOUS_WORDS
        ) else 0,
        "is_shortened": 1 if full_domain.lower() in SHORTENER_DOMAINS else 0,
        "num_query_params": query.count("=") if query else 0,
 
        # --- Entropy (randomness) of the domain name ---
        "domain_entropy": round(_shannon_entropy(domain), 3),
 
        # --- Domain reputation (whitelist against known popular domains) ---
        "is_trusted_domain": 1 if full_domain.lower() in _load_trusted_domains() else 0,
 
        # --- Restricted-eligibility TLD (hard to spoof regardless of
        # global popularity, since registration itself requires proof
        # of banking license / government / academic accreditation) ---
        "is_restricted_tld": 1 if suffix.lower() in RESTRICTED_ELIGIBILITY_SUFFIXES else 0,
 
        # --- Ratio features ---
        "digit_ratio": round(
            sum(c.isdigit() for c in url) / len(url), 3
        ) if url else 0,
    }
    features.update(_v2_features(url, parsed, subdomain, domain, suffix, path, query))
 
    # TODO (content-based, requires fetching the page — do this in a
    # separate, rate-limited, sandboxed step, not inline here):
    #   - has_password_field: form with type="password" present
    #   - has_iframe: hidden/zero-size iframe present
    #   - external_link_ratio: fraction of <a> hrefs pointing off-domain
    #   - favicon_domain_mismatch: favicon loaded from a different domain
 
    # TODO (WHOIS-based, requires `python-whois` + a network call):
    #   - domain_age_days: newly registered domains are a strong phishing
    #     signal — most legitimate sites are months/years old
 
    return features
 
 
if __name__ == "__main__":
    # Quick manual sanity check
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.tk/verify/account?id=283991",
        "http://192.168.1.1/banking/confirm",
    ]
    for u in test_urls:
        print(u)
        for k, v in extract_features(u).items():
            print(f"  {k}: {v}")
        print()