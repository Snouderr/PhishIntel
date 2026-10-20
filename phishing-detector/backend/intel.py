"""
Threat-intel enrichment. Everything here works WITHOUT any API key:

  rdap_domain(d)     registration date / age, registrar, expiry  (rdap.org)
  dns_records(d)     A / MX / NS / SPF / DMARC                    (dnspython)
  ip_info(ip)        ASN, network owner, country, reverse DNS    (Team Cymru over DNS)
  blocklist_check(u) local phishing DB (Phishing.Database dump, ~780k URLs
                     + ~500k hosts, built into SQLite) + OpenPhish community feed

Optional, only when a key is set in .env:
  urlhaus_lookup(u)    abuse.ch URLhaus   (URLHAUS_AUTH_KEY)
  virustotal_lookup(u) VirusTotal v3      (VIRUSTOTAL_API_KEY)

All lookups are cached in memory and fail soft: a network error comes back
as {"error": "..."} instead of raising, so one dead service never breaks
an investigation.
"""

import base64
import os
import sqlite3
import tarfile
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dns.reversename
import httpx

from feature_extraction import SHORTENER_DOMAINS, _load_trusted_domains, get_full_domain

HTTP_TIMEOUT = 8.0
USER_AGENT = "PhishIntel/1.0 (phishing investigation tool; educational project)"

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
LINKS_ARCHIVE = os.path.join(DATA_DIR, "ALL-phishing-links.tar.gz")
DOMAINS_ARCHIVE = os.path.join(DATA_DIR, "ALL-phishing-domains.tar.gz")
BLOCKLIST_DB = os.path.join(DATA_DIR, "phishdb.sqlite")
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Hosts shared by many unrelated users. A phishing list containing the bare
# host (e.g. "sites.google.com") only means *some* page there was phishing,
# so a host-level hit on these says nothing about the URL being checked.
SHARED_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "onedrive.live.com", "1drv.ms", "dropbox.com", "dl.dropboxusercontent.com",
    "github.io", "github.com", "raw.githubusercontent.com", "gitlab.io",
    "notion.site", "webflow.io", "wixsite.com", "weebly.com", "blogspot.com",
    "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "web.app",
    "firebaseapp.com", "ipfs.io", "dweb.link", "duckdns.org", "ngrok.io",
}


# ─── tiny TTL cache ──────────────────────────────────────────────────────

class _TTLCache:
    def __init__(self, ttl: float, max_items: int = 2000):
        self.ttl, self.max_items = ttl, max_items
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            hit = self._data.get(key)
            if hit and time.time() - hit[0] < self.ttl:
                return hit[1]
            return None

    def set(self, key, value):
        with self._lock:
            if len(self._data) >= self.max_items:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.time(), value)
        return value


_cache = _TTLCache(ttl=6 * 3600)


def _cached(prefix):
    def deco(fn):
        def wrapper(arg):
            key = f"{prefix}:{arg}"
            hit = _cache.get(key)
            if hit is not None:
                return hit
            result = fn(arg)
            # Don't pin transient failures for 6 hours
            if not (isinstance(result, dict) and result.get("error")):
                _cache.set(key, result)
            return result
        wrapper.__wrapped__ = fn
        return wrapper
    return deco


def _http() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT})


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 4.0
    return r


# ─── RDAP (domain age) ───────────────────────────────────────────────────

def parse_rdap(data: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registered = events.get("registration")
    age_days = None
    if registered:
        try:
            dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (now - dt).days
        except ValueError:
            pass

    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
            registrar = registrar or ent.get("handle")
    return {
        "registered": registered,
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "age_days": age_days,
        "registrar": registrar,
        "status": data.get("status", []),
        "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])],
    }


@_cached("rdap")
def rdap_domain(domain: str) -> dict:
    domain = get_full_domain(domain)
    try:
        with _http() as c:
            r = c.get(f"https://rdap.org/domain/{domain}",
                      headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return {"domain": domain, "found": False}
        r.raise_for_status()
        return {"domain": domain, "found": True, **parse_rdap(r.json())}
    except (httpx.HTTPError, ValueError) as e:
        return {"domain": domain, "error": f"RDAP lookup failed: {e.__class__.__name__}"}


# ─── DNS ─────────────────────────────────────────────────────────────────

@_cached("dns")
def dns_records(domain: str) -> dict:
    res = _resolver()
    out = {"domain": domain, "exists": True}

    def q(name, rtype):
        try:
            return [r.to_text() for r in res.resolve(name, rtype)]
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.resolver.NXDOMAIN:
            raise
        except dns.exception.DNSException:
            return None  # timeout etc. — unknown, not "empty"

    try:
        out["a"] = q(domain, "A")
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "exists": False}
    try:
        out["mx"] = q(domain, "MX")
        out["ns"] = q(domain, "NS")
        txt = q(domain, "TXT") or []
        txt = [t.strip('"').replace('" "', "") for t in txt]  # rejoin 255-char chunks
        out["spf"] = next((t for t in txt if "v=spf1" in t), None)
        dmarc = q(f"_dmarc.{domain}", "TXT") or []
        out["dmarc"] = next((t.strip('"') for t in dmarc if "v=DMARC1" in t), None)
    except dns.resolver.NXDOMAIN:
        out.update({"mx": [], "ns": [], "spf": None, "dmarc": None})
    if out["a"] is None:
        out["error"] = "DNS lookup timed out"
    return out


# ─── IP → ASN (Team Cymru, over DNS, no key) ─────────────────────────────

def _cymru_fields(txt: str) -> list:
    return [p.strip() for p in txt.strip('"').split("|")]


@_cached("ip")
def ip_info(ip: str) -> dict:
    res = _resolver()
    out = {"ip": ip}
    try:
        rev = ".".join(reversed(ip.split(".")))
        origin = _cymru_fields(res.resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0].to_text())
        out.update({"asn": origin[0].split()[0], "prefix": origin[1], "country": origin[2],
                    "registry": origin[3]})
        asn_txt = _cymru_fields(res.resolve(f"AS{out['asn']}.asn.cymru.com", "TXT")[0].to_text())
        out["as_name"] = asn_txt[-1]
    except dns.resolver.NXDOMAIN:
        out["asn"] = None  # unannounced / private space
    except dns.exception.DNSException as e:
        out["error"] = f"ASN lookup failed: {e.__class__.__name__}"
    try:
        out["ptr"] = res.resolve(dns.reversename.from_address(ip), "PTR")[0].to_text().rstrip(".")
    except (dns.exception.DNSException, ValueError):
        out["ptr"] = None
    return out


# ─── Blocklists ──────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Scheme-less, lower-cased host, no trailing slash — the lookup key."""
    url = url.strip()
    p = urlparse(url if "://" in url else "http://" + url)
    host = (p.hostname or "").lower()
    rest = p.path + (("?" + p.query) if p.query else "")
    return (host + rest).rstrip("/")


def _host_hit_counts(host: str) -> bool:
    """Is a host-level blocklist hit on this host meaningful?"""
    host = host.lower().removeprefix("www.")
    if host in SHARED_HOSTS or host in SHORTENER_DOMAINS:
        return False
    # The bare apex of a popular site (e.g. "google.com") — a listing there
    # is about one page, not the whole site.
    return not (host == get_full_domain(host) and host in _load_trusted_domains())


_db_lock = threading.Lock()


def build_blocklist_db(links_archive=LINKS_ARCHIVE, domains_archive=DOMAINS_ARCHIVE,
                       db_path=BLOCKLIST_DB) -> dict:
    """One-time import of the tar.gz lists into an indexed SQLite file."""
    tmp = db_path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute("CREATE TABLE urls (u TEXT PRIMARY KEY) WITHOUT ROWID")
    con.execute("CREATE TABLE hosts (h TEXT PRIMARY KEY) WITHOUT ROWID")
    counts = {}
    for archive, table, norm in ((links_archive, "urls", normalize_url),
                                 (domains_archive, "hosts", lambda s: s.strip().lower())):
        n = 0
        if os.path.exists(archive):
            with tarfile.open(archive, "r:gz") as tar:
                member = next(m for m in tar.getmembers() if m.isfile())
                f = tar.extractfile(member)
                batch = []
                for line in f:
                    line = line.decode("utf-8", "ignore").strip()
                    if line and not line.startswith("#"):
                        batch.append((norm(line),))
                    if len(batch) >= 50_000:
                        con.executemany(f"INSERT OR IGNORE INTO {table} VALUES (?)", batch)
                        n += len(batch)
                        batch = []
                con.executemany(f"INSERT OR IGNORE INTO {table} VALUES (?)", batch)
                n += len(batch)
        counts[table] = n
    built = datetime.fromtimestamp(
        os.path.getmtime(links_archive) if os.path.exists(links_archive) else time.time(),
        timezone.utc).date().isoformat()
    con.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
    con.execute("INSERT INTO meta VALUES ('list_date', ?)", (built,))
    con.commit()
    con.close()
    os.replace(tmp, db_path)
    return counts


def _blocklist_conn():
    with _db_lock:
        if not os.path.exists(BLOCKLIST_DB):
            if not os.path.exists(LINKS_ARCHIVE):
                return None
            build_blocklist_db()
    return sqlite3.connect(f"file:{BLOCKLIST_DB}?mode=ro", uri=True, check_same_thread=False)


def blocklist_available() -> bool:
    return os.path.exists(BLOCKLIST_DB) or os.path.exists(LINKS_ARCHIVE)


_openphish = {"ts": 0.0, "urls": set(), "hosts": set(), "error": None}
_openphish_lock = threading.Lock()


def _openphish_feed():
    with _openphish_lock:
        if time.time() - _openphish["ts"] < 6 * 3600:
            return _openphish
        try:
            with _http() as c:
                r = c.get(OPENPHISH_FEED)
            r.raise_for_status()
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            _openphish.update(urls={normalize_url(l) for l in lines},
                              hosts={(urlparse(l).hostname or "").lower() for l in lines},
                              error=None)
        except httpx.HTTPError as e:
            _openphish["error"] = f"OpenPhish feed unavailable: {e.__class__.__name__}"
        _openphish["ts"] = time.time()
        return _openphish


def blocklist_check(url: str) -> dict:
    key = normalize_url(url)
    host = key.split("/", 1)[0].split("?", 1)[0]
    host_ok = _host_hit_counts(host)
    out = {"local": None, "openphish": None}

    con = _blocklist_conn()
    if con is not None:
        try:
            url_hit = con.execute("SELECT 1 FROM urls WHERE u = ?", (key,)).fetchone() is not None
            host_hit = host_ok and con.execute(
                "SELECT 1 FROM hosts WHERE h = ?", (host.removeprefix("www."),)).fetchone() is not None
            list_date = con.execute("SELECT v FROM meta WHERE k='list_date'").fetchone()
            out["local"] = {"url_match": url_hit, "host_match": host_hit,
                            "list_date": list_date[0] if list_date else None}
        finally:
            con.close()

    feed = _openphish_feed()
    if feed["urls"]:
        out["openphish"] = {"url_match": key in feed["urls"],
                            "host_match": host_ok and host in feed["hosts"]}
    elif feed["error"]:
        out["openphish"] = {"error": feed["error"]}

    out["listed"] = any(isinstance(v, dict) and (v.get("url_match") or v.get("host_match"))
                        for v in (out["local"], out["openphish"]))
    return out


# ─── Optional keyed services ─────────────────────────────────────────────

@_cached("urlhaus")
def urlhaus_lookup(url: str) -> dict | None:
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return None
    try:
        with _http() as c:
            r = c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                       headers={"Auth-Key": key})
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return {"listed": False, "status": d.get("query_status")}
        return {"listed": True, "threat": d.get("threat"), "url_status": d.get("url_status"),
                "tags": d.get("tags") or [], "reference": d.get("urlhaus_reference")}
    except (httpx.HTTPError, ValueError) as e:
        return {"error": f"URLhaus lookup failed: {e.__class__.__name__}"}


@_cached("vt")
def virustotal_lookup(url: str) -> dict | None:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        with _http() as c:
            r = c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
        if r.status_code == 404:
            return {"seen": False}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"seen": True, "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values())}
    except (httpx.HTTPError, ValueError, KeyError) as e:
        return {"error": f"VirusTotal lookup failed: {e.__class__.__name__}"}


def intel_status() -> dict:
    return {
        "rdap": True, "dns": True, "asn": True, "openphish": True,
        "local_blocklist": blocklist_available(),
        "urlhaus": bool(os.getenv("URLHAUS_AUTH_KEY")),
        "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
    }


if __name__ == "__main__":
    t = time.time()
    print("Building blocklist DB…", build_blocklist_db(), f"{time.time() - t:.1f}s")
