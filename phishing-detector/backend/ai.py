"""
AI summaries for PhishIntel, with three providers:

  template  Built from the analysis findings — offline, deterministic, always on.
  ollama    Local LLM via Ollama (http://localhost:11434) — nothing leaves the machine.
  gemini    Google Gemini API — only if GEMINI_API_KEY is set in .env.

Privacy by design:
  * Only facts the analysis derived are sent (headers, findings, flags, IOCs) —
    never the raw email body.
  * redact=True (the default) removes recipients, masks their names/addresses
    wherever they appear, and replaces URL query values and token-like path
    segments with placeholders.
  * build_prompt() is exposed so the UI can show exactly what would be sent
    before anything goes to a cloud provider.
"""

import json
import os
import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_FALLBACK_MODEL = "gemini-flash-latest"  # alias Google keeps pointed at a current model
OLLAMA_DEFAULT_MODEL = "llama3.1:8b"

SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing part of a phishing investigation report. "
    "Use ONLY the facts provided; do not invent indicators, dates, or actor names. "
    "If something is unknown, say so. Write plain text without markdown, headings or bullet symbols. "
    "Be concise and specific."
)

TASKS = {
    "headers": "Explain what the sender identity and authentication results show "
               "(SPF/DKIM/DMARC, spoofing, mismatched Reply-To/Return-Path, mail route). Max 120 words.",
    "urls": "Analyse the links and attachments: what each one is likely for, which flags matter, "
            "and what the victim would experience on clicking. Max 120 words.",
    "iocs": "Correlate the indicators: which belong to attacker infrastructure, which are shared "
            "services, and what to block first. Max 120 words.",
    "infra": "Profile the attacker infrastructure from domain ages, registrars, hosting ASNs and "
             "blocklist hits. Max 120 words.",
    "executive": "Write a 3-sentence executive summary for a non-technical manager: what happened, "
                 "how risky it is, and what has to be done.",
}


# ─── facts + redaction ───────────────────────────────────────────────────

def _redact_url(url: str) -> str:
    try:
        p = urlparse(url)
    except ValueError:
        return url
    path = re.sub(r"/[A-Za-z0-9_\-=]{20,}", "/[token]", p.path)
    query = urlencode([(k, "[redacted]") for k, _ in parse_qsl(p.query, keep_blank_values=True)],
                      safe="[]")
    return urlunparse((p.scheme, p.netloc, path, p.params, query, ""))


def _redact(obj, recipients: list):
    """Walk a JSON-like object, masking recipient identity and URL secrets."""
    needles = set()
    for addr in recipients:
        addr = addr.lower()
        needles.add(addr)
        local, _, domain = addr.partition("@")
        if domain:
            needles.add(domain)
        if len(local) >= 3:
            needles.add(local)
            needles.update(p for p in re.split(r"[._\-+]", local) if len(p) >= 3)
    patterns = [re.compile(re.escape(n), re.I) for n in sorted(needles, key=len, reverse=True)]

    def scrub(s: str) -> str:
        s = re.sub(r"https?://\S+", lambda m: _redact_url(m.group(0)), s)
        for p in patterns:
            s = p.sub("[recipient]", s)
        return s

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items() if k not in ("to", "body_preview")}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            return scrub(o)
        return o

    return walk(obj)


def build_facts(kind: str, case: dict, redact: bool = True) -> dict:
    """Pick only what this stage needs from the case the UI sends."""
    h = case.get("headers") or {}
    all_findings = case.get("findings") or []
    if kind == "headers":  # only sender / auth / routing issues belong in this stage
        all_findings = [f for f in all_findings if f.get("category") in ("auth", "sender", "routing")]
    findings = [{k: f.get(k) for k in ("severity", "title", "detail")} for f in all_findings]
    urls = [{"url": u.get("url"), "flags": u.get("flags"), "link_text": u.get("link_text") or None,
             "ml_phishing_probability": (u.get("ml") or {}).get("phishing_probability"),
             "ml_reasons": [r.get("reason") for r in (u.get("ml") or {}).get("reasons") or []] or None,
             "blocklisted": (u.get("intel") or {}).get("listed")}
            for u in case.get("urls") or []]
    attachments = [{k: a.get(k) for k in ("filename", "content_type", "sha256")}
                   for a in case.get("attachments") or []]
    iocs = [{k: i.get(k) for k in ("type", "indicator", "detail", "severity")}
            for i in case.get("iocs") or []]
    sender = {k: h.get(k) for k in ("from_name", "from_address", "reply_to", "return_path",
                                    "subject", "date")}

    facts = {"verdict": case.get("verdict")}
    if kind == "headers":
        facts.update(sender=sender, auth={k: (case.get("auth") or {}).get(k)
                                          for k in ("spf", "dkim", "dmarc", "spam_score")},
                     mail_route=[{k: hop.get(k) for k in ("from", "ip", "by")}
                                 for hop in case.get("hops") or []],
                     findings=[f for f in findings if f["severity"] != "info"])
    elif kind == "urls":
        facts.update(urls=urls, attachments=attachments, findings=findings)
    elif kind == "iocs":
        facts.update(iocs=iocs)
    elif kind == "infra":
        facts.update(enrichment=case.get("enrichment") or {}, iocs=iocs)
    else:  # executive
        facts.update(sender=sender, findings=findings, urls=urls, attachments=attachments,
                     enrichment=case.get("enrichment") or {})

    if redact:
        facts = _redact(facts, h.get("to") or [])
    return facts


def build_prompt(kind: str, case: dict, redact: bool = True) -> str:
    if kind not in TASKS:
        raise ValueError(f"Unknown summary kind: {kind}")
    facts = build_facts(kind, case, redact)
    return (f"Task: {TASKS[kind]}\n\nInvestigation facts (JSON):\n"
            f"{json.dumps(facts, indent=1, ensure_ascii=False, default=str)}")


# ─── template provider (offline) ─────────────────────────────────────────

def _names(items, key="title", n=4):
    vals = [str(i.get(key)) for i in items][:n]
    return ", ".join(vals) if vals else "none"


def template_summary(kind: str, case: dict) -> str:
    f = build_facts(kind, case, redact=False)
    v = f.get("verdict") or {}
    level = v.get("label", "Unknown verdict")
    high = [x for x in case.get("findings") or [] if x.get("severity") == "high"]

    if kind == "headers":
        a, s = f["auth"], f["sender"]
        fails = [k.upper() for k in ("spf", "dkim", "dmarc") if a.get(k) != "pass"]
        origin = next((h for h in f["mail_route"] if h.get("ip")), None)
        out = [f"The message claims to come from {s.get('from_name') or 'an unnamed sender'} "
               f"<{s.get('from_address')}>."]
        out.append(f"Authentication: SPF {a.get('spf')}, DKIM {a.get('dkim')}, DMARC {a.get('dmarc')}"
                   + (f" ({', '.join(fails)} not passing)." if fails else " (all passing)."))
        sender_issues = [x for x in f["findings"] if x["title"] not in
                         ("SPF fail", "SPF softfail", "DKIM none", "DKIM fail", "DMARC fail")]
        if sender_issues:
            out.append(f"Sender red flags: {_names(sender_issues)}.")
        if origin:
            out.append(f"It entered the mail system from {origin['ip']} ({origin.get('from') or 'unknown host'}).")
        out.append(f"Header verdict contribution: {level}.")
        return " ".join(out)

    if kind == "urls":
        urls = f["urls"]
        flagged = [u for u in urls if [x for x in u["flags"] or [] if x != "no-https"]
                   or (u["ml_phishing_probability"] or 0) >= 0.5 or u["blocklisted"]]
        out = [f"{len(urls)} link(s) found, {len(flagged)} suspicious."]
        for u in flagged[:4]:
            bits = [x for x in u["flags"] or [] if x != "no-https"]
            if u["ml_phishing_probability"] is not None:
                bits.append(f"ML {round(u['ml_phishing_probability'] * 100)}% phishing")
            if u["blocklisted"]:
                bits.append("on a phishing blocklist")
            out.append(f"{u['url']}: {', '.join(bits) or 'suspicious'}.")
        if f["attachments"]:
            out.append(f"Attachments: {_names(f['attachments'], 'filename')}.")
        return " ".join(out)

    if kind == "iocs":
        iocs = f["iocs"]
        by_type = {}
        for i in iocs:
            by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        crit = [i for i in iocs if i["severity"] in ("critical", "high")]
        return (f"{len(iocs)} indicators collected ("
                + ", ".join(f"{n} {t}" for t, n in by_type.items())
                + f"). {len(crit)} are rated critical/high and should be blocked first: "
                + _names(crit, "indicator", 5) + ".")

    if kind == "infra":
        out = []
        for d, e in (f["enrichment"].get("domains") or {}).items():
            rd = e.get("rdap") or {}
            if rd.get("found") is False:
                out.append(f"{d} is not registered (taken down or never existed).")
            elif rd.get("age_days") is not None:
                out.append(f"{d} was registered {rd['age_days']} days ago via {rd.get('registrar') or 'unknown registrar'}.")
        for ip, e in (f["enrichment"].get("ips") or {}).items():
            if e.get("asn"):
                out.append(f"{ip} is announced by AS{e['asn']} ({e.get('as_name')}, {e.get('country')}).")
        return " ".join(out) or "No enrichment data has been collected yet."

    # executive
    if v.get("level") == "low":
        return ("This email was analysed and shows no strong signs of phishing. "
                "Sender authentication passed and no malicious links or attachments were identified. "
                "No action is needed beyond normal monitoring.")
    return (f"A suspicious email from {f['sender'].get('from_address')} was assessed as {level.lower()} "
            f"(risk score {v.get('score')}). Key indicators: {_names(high, n=3)}. "
            "The sender and linked infrastructure should be blocked, matching messages purged, "
            "and any user who interacted with it should reset their credentials.")


# ─── LLM providers ───────────────────────────────────────────────────────

def _clean(text: str) -> str:
    text = re.sub(r"\*\*|__|^#+\s*|^\s*[-*•]\s+", "", text, flags=re.M)
    return text.strip()


def ollama_status() -> dict:
    base = os.getenv("OLLAMA_URL", "http://localhost:11434")
    want = os.getenv("OLLAMA_MODEL") or OLLAMA_DEFAULT_MODEL
    try:
        r = httpx.get(f"{base}/api/tags", timeout=1.5)
        models = [m["name"] for m in r.json().get("models", [])]
    except (httpx.HTTPError, ValueError, KeyError):
        return {"available": False, "model": None, "models": []}
    model = want if want in models else (models[0] if models else None)
    return {"available": bool(model), "model": model, "models": models}


def ollama_generate(prompt: str) -> tuple[str, str]:
    status = ollama_status()
    if not status["available"]:
        raise RuntimeError("Ollama is not running or has no models (try: ollama pull llama3.1:8b)")
    base = os.getenv("OLLAMA_URL", "http://localhost:11434")
    r = httpx.post(f"{base}/api/chat", timeout=180, json={
        "model": status["model"], "stream": False, "options": {"temperature": 0.2},
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": prompt}],
    })
    r.raise_for_status()
    return _clean(r.json()["message"]["content"]), status["model"]


_gemini_models_cache = {}

# Overloaded / rate-limited / transient — worth a retry or another model.
GEMINI_RETRYABLE = {429, 500, 502, 503, 504}
GEMINI_TIMEOUT = 45


def rank_gemini_models(models: list) -> list[str]:
    """
    Usable text models, best first: stable full 'flash' models (newest
    first), then 'flash-lite' ones — lighter and usually less loaded, so a
    good fallback when the main model is busy.
    """
    skip = ("image", "tts", "live", "audio", "embedding", "thinking", "exp", "native",
            "robotics", "transcribe", "translate")
    full, lite = [], []
    for m in models:
        name = m.get("name", "").removeprefix("models/")
        if ("generateContent" not in m.get("supportedGenerationMethods", [])
                or "flash" not in name or any(s in name for s in skip)):
            continue
        ver = re.search(r"gemini-(\d+(?:\.\d+)?)", name)
        key = ("preview" not in name, float(ver.group(1)) if ver else 0.0,
               not re.search(r"-\d{3,}$", name), name)
        (lite if "lite" in name else full).append(key)
    return [k[3] for k in sorted(full, reverse=True)] + [k[3] for k in sorted(lite, reverse=True)]


def pick_gemini_model(models: list) -> str | None:
    """Newest stable general-purpose 'flash' text model the key can use."""
    ranked = [m for m in rank_gemini_models(models) if "lite" not in m]
    return ranked[0] if ranked else None


def _gemini_candidates(key: str) -> list[str]:
    """Models to try in order: the main pick, one runner-up, one lite model."""
    if os.getenv("GEMINI_MODEL"):
        return [os.getenv("GEMINI_MODEL")]
    if key in _gemini_models_cache:
        return _gemini_models_cache[key]
    try:
        r = httpx.get(f"{GEMINI_BASE}/models", params={"pageSize": 200},
                      headers={"x-goog-api-key": key}, timeout=10)
        r.raise_for_status()
        ranked = rank_gemini_models(r.json().get("models", []))
    except (httpx.HTTPError, ValueError):
        return [GEMINI_FALLBACK_MODEL]  # don't cache — retry the listing next time
    full = [m for m in ranked if "lite" not in m][:2]
    lite = [m for m in ranked if "lite" in m][:1]
    _gemini_models_cache[key] = (full + lite) or [GEMINI_FALLBACK_MODEL]
    return _gemini_models_cache[key]


def _gemini_error(r) -> str:
    try:
        return r.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        return r.text[:200]


def gemini_generate(prompt: str) -> tuple[str, str]:
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set in backend/.env")
    tried = []
    for model in _gemini_candidates(key):
        gen_config = {"temperature": 0.2, "maxOutputTokens": 2048}
        ver = re.search(r"gemini-(\d+)", model)
        if ver and int(ver.group(1)) >= 3:
            # Summarising facts we already derived needs little reasoning; the
            # default level spends ~1.5k "thinking" tokens and 60–100 s.
            gen_config["thinkingConfig"] = {"thinkingLevel": "low"}
        for attempt in range(2):
            try:
                r = httpx.post(f"{GEMINI_BASE}/models/{model}:generateContent",
                               headers={"x-goog-api-key": key}, timeout=GEMINI_TIMEOUT, json={
                                   "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                                   "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                                   "generationConfig": gen_config,
                               })
            except httpx.TimeoutException:
                tried.append(f"{model} timed out")
                break  # a slow model stays slow — move on
            if r.status_code in GEMINI_RETRYABLE:
                tried.append(f"{model} busy ({r.status_code})")
                if attempt == 0:
                    time.sleep(2)
                    continue
                break
            if r.status_code == 404:  # model retired / not available to this key
                tried.append(f"{model} unavailable")
                break
            if r.status_code >= 400:  # bad key, quota, bad request — another model won't help
                raise RuntimeError(f"Gemini error {r.status_code}: {_gemini_error(r)}")
            data = r.json()
            parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
            # Parts flagged as thoughts are the model's reasoning, not the answer
            text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
            if not text:
                reason = (data.get("candidates") or [{}])[0].get("finishReason") or \
                    data.get("promptFeedback", {}).get("blockReason", "empty response")
                raise RuntimeError(f"Gemini returned no text ({reason})")
            return _clean(text), model
    raise RuntimeError("Gemini is busy right now (" + "; ".join(tried) +
                       "). Try again in a minute, or switch to Built-in / Ollama.")


def providers_status() -> dict:
    return {
        "template": {"available": True, "local": True},
        "ollama": {**ollama_status(), "local": True},
        "gemini": {"available": bool(os.getenv("GEMINI_API_KEY")), "local": False,
                   "model": os.getenv("GEMINI_MODEL") or None},
    }


def summarize(kind: str, case: dict, provider: str = "template", redact: bool = True) -> dict:
    if kind not in TASKS:
        raise ValueError(f"Unknown summary kind: {kind}")
    if provider == "template":
        return {"text": template_summary(kind, case), "provider": "template", "model": None}
    prompt = build_prompt(kind, case, redact)
    if provider == "ollama":
        text, model = ollama_generate(prompt)
    elif provider == "gemini":
        text, model = gemini_generate(prompt)
    else:
        raise ValueError(f"Unknown provider: {provider}")
    return {"text": text, "provider": provider, "model": model, "redacted": redact}
