"""
Phishing email analysis: parses a raw email (headers + MIME body) and
extracts everything an analyst needs for triage.

    analyze_email(raw) -> dict with:
      headers      key sender/recipient/routing headers
      auth         SPF / DKIM / DMARC results + spam-filter verdict
      hops         Received chain, oldest (origin) first
      urls         every URL in the text/HTML bodies, with link text + flags
      attachments  filename, type, size, MD5/SHA-256
      findings     rule hits, each with a severity and a human reason
      verdict      overall level + score derived from the findings
      iocs         deduplicated indicators ready for export

Only the Python standard library is used, so this works offline and never
contacts anything mentioned in the email.
"""

import hashlib
import ipaddress
import re
from email import message_from_string, policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

import attack
from brands import BRAND_DOMAINS, LEET as _LEET, LEET_I as _LEET_I, brand_matches
from feature_extraction import SHORTENER_DOMAINS, get_full_domain

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin 24 hours\b",
    r"\b(account|access) (will be )?(suspended|locked|disabled|closed)\b",
    r"\bverify your (account|identity|details)\b", r"\bunusual (sign-?in|activity)\b",
    r"\bpassword (expires|expired|reset)\b", r"\bfinal (notice|warning|reminder)\b",
    r"\bkyc\b", r"\bconfirm your (payment|details|information)\b",
]

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat",
    ".cmd", ".ps1", ".lnk", ".iso", ".img", ".one", ".html", ".htm", ".svg",
    ".docm", ".xlsm", ".pptm", ".jar", ".msi",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}
HTML_ATTACHMENT_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".svg"}

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}

_URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]+""")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TRAILING_PUNCT = ".,;:!?)'\""


# ─── helpers ─────────────────────────────────────────────────────────────

def refang(text: str) -> str:
    """Undo common defanging so 'hxxp://evil[.]com' is analysed as a URL."""
    text = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", text)
    for fanged in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        text = text.replace(fanged, ".")
    return text.replace("[:]", ":")


def _domain_of_address(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().strip(">") if "@" in addr else ""


def _registered(domain: str) -> str:
    return get_full_domain(domain) if domain else ""


def _is_internal_ip(ip: str) -> bool:
    """RFC1918 / loopback / link-local / CGNAT — never useful as an IOC."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    internal_nets = [ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    )]
    return addr.is_loopback or addr.is_link_local or addr.is_unspecified or any(
        addr in n for n in internal_nets
    )


def _brand_lookalike(domain: str):
    """Return the brand a domain imitates, or None if it's legit/unrelated."""
    reg = _registered(domain)
    if not reg or _is_legit_brand_domain(reg):
        return None
    # Everything left of the registered domain's suffix: subdomains + label
    # (login-microsoftonline.account-verify), with digit look-alikes undone
    # so micros0ft / paypa1 still match.
    host_part = domain.lower()[: -len(reg)] + reg.split(".")[0]
    # "1" stands in for both "l" (paypa1) and "i" (m1crosoft) — try both readings
    for normalized in {host_part.translate(_LEET), host_part.translate(_LEET_I)}:
        tokens = set(re.split(r"[-_.]+", normalized))
        for brand in BRAND_DOMAINS:
            # Short brands (sbi, dhl) only as a whole token, or they match
            # inside unrelated words; longer ones anywhere (docusign-secure,
            # paypalverify, paypal.verify-acct.com).
            if brand_matches(brand, normalized, tokens):
                return brand
    return None


def _is_legit_brand_domain(registered_domain: str) -> bool:
    return any(registered_domain in legit for legit in BRAND_DOMAINS.values())


def _brand_in_text(text: str):
    t = text.lower()
    for brand in BRAND_DOMAINS:
        if re.search(rf"\b{re.escape(brand)}\b", t):
            return brand
    return None


class _LinkExtractor(HTMLParser):
    """Collects <a href> with visible text, plus <form action> targets."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []   # (href, text)
        self.forms = []   # action urls
        self._href = None
        self._text = []
        self.text_chunks = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "form" and a.get("action"):
            self.forms.append(a["action"])

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None

    def handle_data(self, data):
        self.text_chunks.append(data)
        if self._href is not None:
            self._text.append(data)


def _clean_url(u: str) -> str:
    u = u.strip().rstrip(_TRAILING_PUNCT)
    if u.lower().startswith("www."):
        u = "http://" + u
    elif u.startswith("//"):  # protocol-relative (common in form actions)
        u = "https:" + u
    return u


def _url_flags(url: str) -> list:
    host = (urlparse(url).hostname or "").lower()
    flags = []
    if _IPV4_RE.fullmatch(host):
        flags.append("ip-host")
    if _registered(host) in SHORTENER_DOMAINS:
        flags.append("shortener")
    if "xn--" in host:
        flags.append("punycode")
    if "@" in urlparse(url).netloc:
        flags.append("userinfo-trick")
    if urlparse(url).scheme == "http":
        flags.append("no-https")
    brand = _brand_lookalike(host)
    if brand:
        flags.append(f"brand-lookalike:{brand}")
    return flags


# ─── parsing ─────────────────────────────────────────────────────────────

def _parse_auth(msg) -> dict:
    auth = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": []}
    results = msg.get_all("Authentication-Results") or []
    # Topmost header = added by the receiving server, the one we trust.
    for header in results:
        auth["raw"].append(str(header))
    seen = set()
    for header in results:
        for mech, value in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", str(header)):
            mech = mech.lower()
            if mech not in seen:
                auth[mech] = value.lower()
                seen.add(mech)
    if "spf" not in seen and msg.get("Received-SPF"):
        m = re.match(r"\s*([a-zA-Z]+)", str(msg["Received-SPF"]))
        if m:
            auth["spf"] = m.group(1).lower()

    spam_status = str(msg.get("X-Spam-Status", "") or "")
    score = None
    m = re.search(r"score=(-?\d+(?:\.\d+)?)", spam_status) or re.search(
        r"(-?\d+(?:\.\d+)?)", str(msg.get("X-Spam-Score", "") or "")
    )
    if m:
        score = float(m.group(1))
    auth["spam_flagged"] = spam_status.lower().startswith("yes") or (
        str(msg.get("X-Spam-Flag", "")).lower() == "yes"
    )
    auth["spam_score"] = score
    return auth


def _parse_hops(msg) -> list:
    hops = []
    for header in reversed(msg.get_all("Received") or []):  # oldest first
        h = " ".join(str(header).split())
        from_m = re.search(r"\bfrom\s+(\S+)", h)
        by_m = re.search(r"\bby\s+(\S+)", h)
        ip_m = re.search(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?", h.split(" by ")[0]) if from_m else None
        date = h.rsplit(";", 1)[1].strip() if ";" in h else ""
        ip = ip_m.group(1) if ip_m else ""
        hops.append({
            "from": from_m.group(1).strip("()[]") if from_m else "",
            "by": by_m.group(1).strip("()[];") if by_m else "",
            "ip": ip,
            "internal": _is_internal_ip(ip) if ip else None,
            "date": date,
        })
    return hops


def _walk_parts(msg):
    """
    Returns (texts, htmls, attachments, html_attachments, images):
      html_attachments  [(filename, html)] — attached .html/.htm/.svg pages
      images            [(name, bytes)]    — every image part, attached or inline
    """
    texts, htmls, attachments, html_attachments, images = [], [], [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        ctype = part.get_content_type()
        if ctype.startswith("image/"):
            payload = part.get_payload(decode=True) or b""
            name = filename or str(part.get("Content-ID", "") or "").strip("<>") or "inline image"
            images.append((name, payload))
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "(unnamed)",
                "content_type": ctype,
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            ext = "." + (filename or "").lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""
            if ctype in ("text/html", "image/svg+xml") or ext in HTML_ATTACHMENT_EXTENSIONS:
                html_attachments.append((filename or "(unnamed)", payload.decode("utf-8", "replace")))
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            htmls.append(content)
        elif ctype.startswith("text/"):
            texts.append(content)
    return texts, htmls, attachments, html_attachments, images


# ─── HTML attachments ────────────────────────────────────────────────────
# Attached .html files are a classic credential-phishing vehicle: they open
# locally (no URL to block), show a fake login form and post the password
# to the attacker, or immediately redirect to a phishing site. They are
# parsed as text here — never rendered or executed.

_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]*content\s*=\s*["'][^"']*?url\s*=\s*['"]?([^"'>\s]+)""", re.I)
_JS_REDIRECT_RE = re.compile(
    r"""(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\()\s*["'`](https?://[^"'`]+)""", re.I)
_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]+type\s*=\s*["']?password""", re.I)
_OBFUSCATION_RE = re.compile(r"\batob\s*\(|\bunescape\s*\(|String\.fromCharCode|\beval\s*\(|document\.write\s*\(\s*(?:atob|unescape)", re.I)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def _scan_html_attachments(html_attachments) -> tuple[list, list]:
    """Returns (url records to add, per-attachment summaries)."""
    urls, summaries = [], []
    for name, html in html_attachments:
        p = _LinkExtractor()
        try:
            p.feed(html)
        except Exception:
            pass
        forms = [a for a in p.forms if a.lower().startswith(("http", "hxxp", "//"))]
        redirects = _META_REFRESH_RE.findall(html) + _JS_REDIRECT_RE.findall(html)
        links = [h for h, _ in p.links if h.lower().startswith(("http", "hxxp"))]
        urls += [(u, "attachment-form", name) for u in forms]
        urls += [(u, "attachment-redirect", name) for u in redirects]
        urls += [(u, "attachment-link", name) for u in links]
        summaries.append({
            "filename": name,
            "external_forms": len(forms),
            "password_field": bool(_PASSWORD_INPUT_RE.search(html)),
            "redirects": len(redirects),
            "links": len(links),
            "obfuscated": bool(_OBFUSCATION_RE.search(html)) and bool(_BASE64_BLOB_RE.search(html)
                                                                      or "fromCharCode" in html),
        })
    return urls, summaries


# ─── QR codes ("quishing") ───────────────────────────────────────────────
# A QR code in an email moves the link off the scanned channel: mail
# filters see an image, and the victim opens the URL on a phone, outside
# corporate protection. Decoded with OpenCV's QR detector (no network).

MAX_IMAGE_BYTES = 10 * 1024 * 1024


def _decode_qr(data: bytes) -> list[str]:
    try:
        import cv2
        import numpy as np
    except ImportError:  # optional dependency — analysis still works without it
        return []
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None:  # not a format OpenCV reads (e.g. GIF) or not an image
        return []
    h, w = img.shape[:2]
    if max(h, w) > 2000:
        scale = 2000 / max(h, w)
        img = cv2.resize(img, (int(w * scale), int(h * scale)))
    detector = cv2.QRCodeDetector()
    candidates = [img]
    if max(h, w) < 400:  # small codes decode more reliably when enlarged
        candidates.append(cv2.resize(img, (w * 3, h * 3), interpolation=cv2.INTER_NEAREST))
    for im in candidates:
        try:
            ok, texts, _, _ = detector.detectAndDecodeMulti(im)
        except cv2.error:
            continue
        found = [t for t in (texts or []) if t]
        if ok and found:
            return found
    return []


def _scan_qr_codes(images) -> list:
    codes = []
    for name, data in images:
        if not data or len(data) > MAX_IMAGE_BYTES:
            continue
        for text in _decode_qr(data):
            codes.append({"image": name, "text": text})
    return codes


def _extract_urls(texts, htmls, extra=()) -> tuple[list, str]:
    """Returns (url records, combined visible text). `extra` adds URLs found
    outside the body text: (url, source, found_in) from attachments / QR codes."""
    found = {}  # url -> record (dict keeps first-seen order)

    def add(url, source, text="", found_in=""):
        url = _clean_url(refang(url))
        if not urlparse(url).hostname:
            return
        rec = found.setdefault(url, {"url": url, "source": source, "link_text": "", "found_in": found_in})
        if text and not rec["link_text"]:
            rec["link_text"] = text

    visible = list(texts)
    # URLs shown as the *text* of a link are what the attacker wants the
    # victim to see (often the real brand site) — not real targets, so
    # they must not be picked up again as standalone URLs / IOCs.
    decoys = set()
    for html in htmls:
        p = _LinkExtractor()
        try:
            p.feed(html)
        except Exception:
            pass
        for href, text in p.links:
            if href.lower().startswith(("http", "www.", "hxxp")):
                add(href, "html-link", text)
                decoys.update(_clean_url(m.group(0)) for m in _URL_RE.finditer(refang(text)))
        for action in p.forms:
            if action.lower().startswith(("http", "hxxp")):
                add(action, "html-form")
        visible.append(" ".join(p.text_chunks))

    combined = "\n".join(visible)
    for m in _URL_RE.finditer(refang(combined)):
        if _clean_url(m.group(0)) not in decoys or _clean_url(m.group(0)) in found:
            add(m.group(0), "text")
    for url, source, found_in in extra:
        add(url, source, found_in=found_in)

    urls = []
    for rec in found.values():
        flags = _url_flags(rec["url"])
        text = rec["link_text"]
        href_host = (urlparse(rec["url"]).hostname or "").lower()
        # Visible text claims a different site than the real target
        shown = _URL_RE.search(refang(text)) if text else None
        if shown:
            shown_host = (urlparse(_clean_url(shown.group(0))).hostname or "").lower()
            if shown_host and _registered(shown_host) != _registered(href_host):
                flags.append("text-href-mismatch")
        rec["domain"] = href_host
        rec["flags"] = flags
        urls.append(rec)
    return urls, combined


# ─── rules ───────────────────────────────────────────────────────────────

def _finding(findings, sev, category, title, detail):
    findings.append({"severity": sev, "category": category, "title": title, "detail": detail})


def _run_rules(headers, auth, hops, urls, attachments, subject_and_body,
               html_summaries=(), qr_codes=()) -> list:
    f = []
    from_domain = headers["from_domain"]
    from_reg = _registered(from_domain)

    # Authentication
    if auth["spf"] in ("fail", "softfail"):
        _finding(f, "high" if auth["spf"] == "fail" else "medium", "auth",
                 f"SPF {auth['spf']}", "Sending server is not authorised to send for this domain.")
    if auth["dkim"] in ("fail", "none"):
        _finding(f, "medium" if auth["dkim"] == "fail" else "low", "auth",
                 f"DKIM {auth['dkim']}", "Message is not cryptographically signed by the sender's domain."
                 if auth["dkim"] == "none" else "DKIM signature failed verification — content may be altered.")
    if auth["dmarc"] == "fail":
        _finding(f, "high", "auth", "DMARC fail",
                 "From domain does not align with an authenticated SPF/DKIM identity.")
    if auth["spam_flagged"]:
        _finding(f, "medium", "auth", "Flagged by spam filter",
                 f"Spam score {auth['spam_score']}" if auth["spam_score"] is not None else "X-Spam-Status: Yes")

    # Sender identity
    for name, field in (("Reply-To", "reply_to"), ("Return-Path", "return_path")):
        other = _domain_of_address(headers[field])
        if other and from_reg and _registered(other) != from_reg:
            _finding(f, "medium" if field == "reply_to" else "low", "sender",
                     f"{name} domain differs from From",
                     f"From uses {from_domain} but {name} is {headers[field]} — replies/bounces go elsewhere.")

    brand = _brand_lookalike(from_domain)
    if brand:
        _finding(f, "high", "sender", "Sender domain imitates a brand",
                 f"{from_domain} contains '{brand}' but is not an official {brand} domain.")
    name_brand = _brand_in_text(headers["from_name"])
    if name_brand and from_reg not in BRAND_DOMAINS[name_brand]:
        _finding(f, "high", "sender", "Display-name spoofing",
                 f"Display name \"{headers['from_name']}\" suggests {name_brand}, but the address is {headers['from_address']}.")
    if "@" in headers["from_name"] and _domain_of_address(headers["from_name"]) != from_domain:
        _finding(f, "high", "sender", "Email address hidden in display name",
                 f"Display name shows \"{headers['from_name']}\" while the real sender is {headers['from_address']}.")

    # Links
    flag_rules = {
        "ip-host": ("high", "Link points to a raw IP address"),
        "shortener": ("medium", "Link uses a URL shortener (hides the destination)"),
        "punycode": ("high", "Punycode / IDN domain (possible homoglyph lookalike)"),
        "userinfo-trick": ("high", "URL uses '@' to disguise the real host"),
        "text-href-mismatch": ("high", "Link text shows a different site than the real target"),
    }
    for u in urls:
        for flag in u["flags"]:
            if flag in flag_rules:
                sev, title = flag_rules[flag]
                _finding(f, sev, "url", title, u["url"])
            elif flag.startswith("brand-lookalike:"):
                _finding(f, "high", "url", "Link domain imitates a brand",
                         f"{u['domain']} looks like {flag.split(':', 1)[1]} but is not official.")
        if u["source"] == "html-form":
            _finding(f, "high", "url", "HTML form submits data to an external site", u["url"])

    # QR codes (quishing)
    for q in qr_codes:
        if _URL_RE.match(refang(q["text"])):
            _finding(f, "medium", "url", "QR code in the email links to a website",
                     f"{q['text']} (in {q['image']}) — phones open it outside email/web filtering")
        else:
            _finding(f, "info", "content", "QR code found (no link)", f"{q['text'][:120]} (in {q['image']})")

    # HTML attachments, read as text
    for s in html_summaries:
        if s["external_forms"] or s["password_field"]:
            what = "a password field" if s["password_field"] else "a form"
            dest = f" posting to {s['external_forms']} external site(s)" if s["external_forms"] else ""
            _finding(f, "high", "attachment", "HTML attachment contains a credential form",
                     f"{s['filename']} has {what}{dest} — opens locally, so URL filters never see it")
        if s["redirects"]:
            _finding(f, "high", "attachment", "HTML attachment redirects to an external site",
                     f"{s['filename']} forwards the victim to another page as soon as it is opened")
        if s["obfuscated"]:
            _finding(f, "medium", "attachment", "Obfuscated script in HTML attachment",
                     f"{s['filename']} decodes hidden content at runtime (atob / eval / fromCharCode)")

    # Attachments
    for a in attachments:
        name = a["filename"].lower()
        ext = "." + name.rsplit(".", 1)[1] if "." in name else ""
        parts = name.split(".")
        if len(parts) > 2 and "." + parts[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"}:
            _finding(f, "high", "attachment", "Double file extension", a["filename"])
        elif ext in RISKY_EXTENSIONS:
            _finding(f, "high", "attachment", "Risky attachment type", f"{a['filename']} ({a['content_type']})")
        elif ext in ARCHIVE_EXTENSIONS:
            _finding(f, "medium", "attachment", "Archive attachment (can hide malware)", a["filename"])

    # Content
    hits = sorted({m.group(0).lower() for p in URGENCY_PATTERNS
                   for m in re.finditer(p, subject_and_body, re.I)})
    if hits:
        _finding(f, "medium" if len(hits) >= 2 else "low", "content",
                 "Urgency / credential-lure language", ", ".join(hits[:6]))

    # Origin
    external = [h for h in hops if h["ip"] and not h["internal"]]
    if external:
        _finding(f, "info", "routing", "Originating IP",
                 f"{external[0]['ip']} ({external[0]['from'] or 'unknown host'})")
    return f


def _verdict(findings) -> dict:
    score = sum(SEVERITY_WEIGHT[x["severity"]] for x in findings)
    if score >= 8:
        level, label = "high", "Likely phishing"
    elif score >= 4:
        level, label = "medium", "Suspicious"
    else:
        level, label = "low", "No strong phishing indicators"
    return {"level": level, "label": label, "score": score}


def _build_iocs(headers, hops, urls, attachments, findings) -> list:
    iocs, seen = [], set()

    def add(type_, value, detail, sev):
        key = (type_, value.lower())
        if value and key not in seen:
            seen.add(key)
            iocs.append({"type": type_, "indicator": value, "detail": detail,
                         "severity": sev, "source": "auto"})

    suspicious_sender = any(x["category"] in ("sender", "auth") and x["severity"] == "high"
                            for x in findings)
    sender_sev = "high" if suspicious_sender else "medium"
    add("Email", headers["from_address"], "Sender address", sender_sev)
    if headers["from_domain"]:
        add("Domain", _registered(headers["from_domain"]), "Sender domain", sender_sev)
    reply = headers["reply_to"]
    if reply and _domain_of_address(reply) != headers["from_domain"]:
        add("Email", reply, "Reply-To (differs from sender)", "high")

    external = [h for h in hops if h["ip"] and not h["internal"]]
    if external:
        add("IP", external[0]["ip"], f"Originating mail server ({external[0]['from']})", sender_sev)

    for u in urls:
        risky = any(not fl == "no-https" for fl in u["flags"])
        sev = "critical" if risky else "medium"
        add("URL", u["url"], "Link in email" + (f" — {', '.join(u['flags'])}" if u["flags"] else ""), sev)
        reg = _registered(u["domain"])
        if _IPV4_RE.fullmatch(u["domain"] or ""):
            add("IP", u["domain"], "IP used in link", "high")
        elif reg and reg not in SHORTENER_DOMAINS and not _is_legit_brand_domain(reg):
            # Shorteners / real brand sites are shared infrastructure —
            # blocking the whole domain would break legitimate mail.
            add("Domain", reg, "Linked domain", sev)

    for a in attachments:
        risky = any(x["category"] == "attachment" and a["filename"] in x["detail"] for x in findings)
        add("Hash", a["sha256"], f"SHA-256 of {a['filename']}", "critical" if risky else "medium")
    return iocs


def analyze_email(raw: str) -> dict:
    raw = raw.replace("\r\n", "\n").lstrip()
    msg = message_from_string(raw, policy=policy.default)

    from_name, from_addr = parseaddr(str(msg.get("From", "") or ""))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "") or ""))
    _, return_path = parseaddr(str(msg.get("Return-Path", "") or ""))
    to = [a for _, a in getaddresses([str(x) for x in (msg.get_all("To") or [])]) if a]

    headers = {
        "from_name": from_name,
        "from_address": from_addr.lower(),
        "from_domain": _domain_of_address(from_addr),
        "reply_to": reply_to.lower(),
        "return_path": return_path.lower(),
        "to": to,
        "subject": str(msg.get("Subject", "") or ""),
        "date": str(msg.get("Date", "") or ""),
        "message_id": str(msg.get("Message-ID", "") or ""),
        "x_mailer": str(msg.get("X-Mailer", "") or ""),
        "x_originating_ip": str(msg.get("X-Originating-IP", "") or "").strip("[] "),
    }

    auth = _parse_auth(msg)
    hops = _parse_hops(msg)
    if headers["x_originating_ip"] and not any(h["ip"] == headers["x_originating_ip"] for h in hops):
        ip = headers["x_originating_ip"]
        hops.insert(0, {"from": "X-Originating-IP", "by": "", "ip": ip,
                        "internal": _is_internal_ip(ip), "date": ""})

    texts, htmls, attachments, html_attachments, images = _walk_parts(msg)
    att_urls, html_summaries = _scan_html_attachments(html_attachments)
    qr_codes = _scan_qr_codes(images)
    qr_urls = [(q["text"], "qr-code", q["image"]) for q in qr_codes if _URL_RE.match(refang(q["text"]))]
    urls, visible_text = _extract_urls(texts, htmls, extra=att_urls + qr_urls)

    findings = _run_rules(headers, auth, hops, urls, attachments,
                          headers["subject"] + "\n" + visible_text,
                          html_summaries=html_summaries, qr_codes=qr_codes)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: order[x["severity"]])
    attack.annotate(findings)

    body_emails = sorted({e.lower() for e in _EMAIL_RE.findall(visible_text)})
    verdict = _verdict(findings)
    iocs = _build_iocs(headers, hops, urls, attachments, findings)
    if verdict["level"] == "low":
        # Nothing malicious found — keep the indicators for the record,
        # but don't present them as things to block.
        for ioc in iocs:
            ioc["severity"] = "low"

    return {
        "headers": headers,
        "auth": auth,
        "hops": hops,
        "urls": urls,
        "attachments": attachments,
        "body_emails": body_emails,
        "body_preview": visible_text.strip()[:2000],
        "findings": findings,
        "verdict": verdict,
        "iocs": iocs,
        "html_attachments": html_summaries,
        "qr_codes": qr_codes,
        "attack": attack.summary(findings),
    }
