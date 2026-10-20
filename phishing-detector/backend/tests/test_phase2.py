"""Phase 2 tests — enrichment, blocklists, AI providers. No real network calls."""

import io
import os
import tarfile
from datetime import datetime, timezone

import pytest

import ai
import intel
from email_analysis import analyze_email

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "..", "phishintel", "samples")


def sample_case(name="docusign.eml"):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        a = analyze_email(f.read())
    return {**a, "urls": [{**u, "ml": {"phishing_probability": 0.86}} for u in a["urls"]]}


# ─── RDAP / ASN parsing ──────────────────────────────────────────────────

RDAP_SAMPLE = {
    "events": [
        {"eventAction": "registration", "eventDate": "2026-10-12T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-10-12T00:00:00Z"},
    ],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"], ["fn", {}, "text", "NameCheap, Inc."]]]}],
    "nameservers": [{"ldhName": "DNS1.REGISTRAR-SERVERS.COM"}],
    "status": ["client transfer prohibited"],
}


def test_parse_rdap():
    r = intel.parse_rdap(RDAP_SAMPLE, now=datetime(2026, 10, 19, tzinfo=timezone.utc))
    assert r["age_days"] == 7
    assert r["registrar"] == "NameCheap, Inc."
    assert r["nameservers"] == ["dns1.registrar-servers.com"]
    assert r["expires"].startswith("2027")


def test_cymru_fields():
    assert intel._cymru_fields('"54113 | 185.199.108.0/22 | US | ripencc | 2015-11-26"')[:3] == \
        ["54113", "185.199.108.0/22", "US"]


# ─── blocklists ──────────────────────────────────────────────────────────

def test_normalize_url():
    assert intel.normalize_url("HTTPS://Evil.COM/Login/") == "evil.com/Login"
    assert intel.normalize_url("evil.com") == "evil.com"


@pytest.mark.parametrize("host,counts", [
    ("sites.google.com", False),        # shared platform
    ("bit.ly", False),                  # shortener
    ("google.com", False),              # popular apex
    ("evil-login.vercel.app", True),    # one specific tenant
    ("apple-id-findmy.com", True),
])
def test_host_hit_counts(host, counts):
    assert intel._host_hit_counts(host) is counts


def _tar(path, name, lines):
    data = "\n".join(lines).encode()
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


@pytest.fixture
def tiny_blocklist(tmp_path, monkeypatch):
    links, domains, db = tmp_path / "l.tar.gz", tmp_path / "d.tar.gz", tmp_path / "db.sqlite"
    _tar(links, "links.lst", ["http://evil-login.com/verify/", "https://sites.google.com/view/phish"])
    _tar(domains, "domains.lst", ["evil-login.com", "sites.google.com", "bad.vercel.app"])
    counts = intel.build_blocklist_db(str(links), str(domains), str(db))
    assert counts == {"urls": 2, "hosts": 3}
    monkeypatch.setattr(intel, "BLOCKLIST_DB", str(db))
    monkeypatch.setattr(intel, "_openphish_feed",
                        lambda: {"urls": {"phish.example/x"}, "hosts": {"phish.example"}, "error": None})


def test_blocklist_url_match(tiny_blocklist):
    r = intel.blocklist_check("https://evil-login.com/verify")
    assert r["local"]["url_match"] and r["listed"]


def test_blocklist_host_match_specific_tenant(tiny_blocklist):
    assert intel.blocklist_check("https://bad.vercel.app/anything")["local"]["host_match"]


def test_blocklist_shared_host_only_exact_url(tiny_blocklist):
    assert not intel.blocklist_check("https://sites.google.com/view/innocent")["listed"]
    assert intel.blocklist_check("https://sites.google.com/view/phish")["listed"]


def test_openphish_match(tiny_blocklist):
    r = intel.blocklist_check("http://phish.example/x")
    assert r["openphish"]["url_match"] and r["listed"]


# ─── AI: redaction, prompts, templates ───────────────────────────────────

def test_redaction_removes_recipient_and_url_secrets():
    case = sample_case("microsoft365.eml")
    prompt = ai.build_prompt("executive", case, redact=True)
    assert "j.doe" not in prompt.lower() and "contoso" not in prompt.lower()
    assert "user=[redacted]" in prompt
    assert "alerts@micros0ft-365-auth.com" in prompt  # attacker data is kept
    assert "body_preview" not in prompt


def test_unredacted_prompt_keeps_url():
    prompt = ai.build_prompt("urls", sample_case("microsoft365.eml"), redact=False)
    assert "user=j.doe" in prompt


def test_prompt_never_contains_body():
    case = sample_case()
    assert case["body_preview"]
    for kind in ai.TASKS:
        assert "You have received a secure document" not in ai.build_prompt(kind, case, redact=False)


@pytest.mark.parametrize("kind", list(ai.TASKS))
def test_template_summaries(kind):
    text = ai.summarize(kind, sample_case(), "template")["text"]
    assert text and "None" not in text


def test_template_executive_low_risk():
    text = ai.template_summary("executive", sample_case("legit-newsletter.eml"))
    assert "no strong signs of phishing" in text


def test_pick_gemini_model():
    gen = ["generateContent"]
    models = [
        {"name": "models/gemini-2.0-flash", "supportedGenerationMethods": gen},
        {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": gen},
        {"name": "models/gemini-2.5-flash-lite", "supportedGenerationMethods": gen},
        {"name": "models/gemini-3.0-flash-preview", "supportedGenerationMethods": gen},
        {"name": "models/gemini-2.5-pro", "supportedGenerationMethods": gen},
        {"name": "models/gemini-2.5-flash-image", "supportedGenerationMethods": gen},
        {"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]},
    ]
    # stable beats preview, then newest version
    assert ai.pick_gemini_model(models) == "gemini-2.5-flash"
    assert ai.pick_gemini_model([]) is None


class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._p = status, payload
        self.text = str(payload)

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ai.httpx.HTTPStatusError("err", request=None, response=None)


def test_gemini_generate_request(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    sent = {}

    def fake_post(url, headers, json, timeout):
        sent.update(url=url, headers=headers, body=json)
        return _Resp(200, {"candidates": [{"content": {"parts": [{"text": "**Summary** here"}]}}]})

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    text, model = ai.gemini_generate("prompt")
    assert text == "Summary here" and model == "gemini-test"
    assert sent["url"].endswith("/models/gemini-test:generateContent")
    assert sent["headers"]["x-goog-api-key"] == "test-key"  # header, not URL
    assert "test-key" not in sent["url"]


def test_gemini_error_message(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "bad")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    monkeypatch.setattr(ai.httpx, "post", lambda *a, **k: _Resp(400, {"error": {"message": "API key not valid"}}))
    with pytest.raises(RuntimeError, match="API key not valid"):
        ai.gemini_generate("prompt")


def test_ollama_unavailable(monkeypatch):
    monkeypatch.setattr(ai, "ollama_status", lambda: {"available": False, "model": None, "models": []})
    with pytest.raises(RuntimeError, match="Ollama is not running"):
        ai.ollama_generate("prompt")


# ─── endpoints ───────────────────────────────────────────────────────────

def test_summarize_endpoint_template(client):
    r = client.post("/ai/summarize", json={"kind": "headers", "case": sample_case()})
    assert r.status_code == 200 and r.json()["provider"] == "template"


def test_summarize_dry_run_shows_prompt(client):
    r = client.post("/ai/summarize", json={"kind": "urls", "case": sample_case(),
                                           "provider": "gemini", "dry_run": True})
    body = r.json()
    assert r.status_code == 200 and body["redacted"] is True
    assert "secure-docverify.com" in body["prompt"]


def test_summarize_gemini_without_key(client, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    r = client.post("/ai/summarize", json={"kind": "urls", "case": {}, "provider": "gemini"})
    assert r.status_code == 503 and "GEMINI_API_KEY" in r.json()["detail"]


def test_summarize_rejects_unknown_kind(client):
    assert client.post("/ai/summarize", json={"kind": "nope", "case": {}}).status_code == 422


def test_enrich_ip_validation(client):
    assert client.post("/enrich/ip", json={"ip": "10.0.0.5"}).json() == {"ip": "10.0.0.5", "private": True}
    assert client.post("/enrich/ip", json={"ip": "not-an-ip"}).status_code == 400


def test_config(client, monkeypatch):
    monkeypatch.setattr(ai, "ollama_status", lambda: {"available": False, "model": None, "models": []})
    body = client.get("/config").json()
    assert body["ai"]["template"]["available"] is True
    assert set(body["intel"]) >= {"rdap", "dns", "local_blocklist", "virustotal"}


def test_headers_summary_excludes_link_findings():
    text = ai.template_summary("headers", sample_case("microsoft365.eml"))
    assert "Link domain imitates a brand" not in text
    assert "Display-name spoofing" in text


def test_rank_gemini_models_lite_last():
    gen = ["generateContent"]
    models = [{"name": f"models/{n}", "supportedGenerationMethods": gen} for n in
              ("gemini-3.5-flash", "gemini-3.8-flash", "gemini-3.8-flash-lite", "gemini-3.5-transcribe",
               "gemini-3.8-flash-tts")]
    assert ai.rank_gemini_models(models) == ["gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.8-flash-lite"]


def test_gemini_falls_back_when_busy(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setattr(ai, "_gemini_candidates", lambda key: ["busy-model", "lite-model"])
    monkeypatch.setattr(ai.time, "sleep", lambda s: None)
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(url)
        if "busy-model" in url:
            return _Resp(503, {"error": {"message": "high demand"}})
        return _Resp(200, {"candidates": [{"content": {"parts": [{"text": "done"}]}}]})

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    assert ai.gemini_generate("p") == ("done", "lite-model")
    assert sum("busy-model" in c for c in calls) == 2  # one retry, then fallback


def test_gemini_all_busy_message(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(ai, "_gemini_candidates", lambda key: ["a"])
    monkeypatch.setattr(ai.time, "sleep", lambda s: None)
    monkeypatch.setattr(ai.httpx, "post", lambda *a, **k: _Resp(503, {}))
    with pytest.raises(RuntimeError, match="Gemini is busy"):
        ai.gemini_generate("p")


def test_gemini_ignores_thought_parts_and_uses_low_thinking(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    sent = {}

    def fake_post(url, headers, json, timeout):
        sent.update(json)
        return _Resp(200, {"candidates": [{"content": {"parts": [
            {"text": "Wait, let me check the JSON...", "thought": True},
            {"text": "Final answer."}]}}]})

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    assert ai.gemini_generate("p")[0] == "Final answer."
    assert sent["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "low"}
