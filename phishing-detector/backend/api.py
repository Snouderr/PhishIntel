"""
Inference API for the phishing detector.
 
Run with:
    uvicorn api:app --reload --port 8000
 
The browser extension POSTs a URL here and gets back a phishing
probability + label. CORS is left open for local extension testing —
tighten this before any real deployment.
"""
 
import ipaddress
import os
from contextlib import asynccontextmanager
from typing import Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Optional API keys (Gemini, VirusTotal, URLhaus) — see .env.example
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

import ai  # noqa: E402  (reads env at call time)
import intel  # noqa: E402
from email_analysis import analyze_email
from feature_extraction import SHORTENER_DOMAINS, extract_features, get_full_domain

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "model_features.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")
# PhishIntel frontend, served from the same origin as the API so the UI
# can call it without CORS and without exposing any API keys client-side.
PHISHINTEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "phishintel")
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        _load_artifacts()
    except RuntimeError as e:
        # Don't crash the server — just report on first request
        print(f"[warn] {e}")
    yield


app = FastAPI(title="Phishing URL Detector API", lifespan=lifespan)

if os.path.isdir(PHISHINTEL_DIR):
    app.mount("/app", StaticFiles(directory=PHISHINTEL_DIR, html=True), name="phishintel")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)
 
_model = None
_feature_cols = None
_scaler = None
 
 
def _load_artifacts():
    global _model, _feature_cols, _scaler
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise RuntimeError(
                "model.pkl not found — run train_model.py first"
            )
        _model = joblib.load(MODEL_PATH)
        _feature_cols = joblib.load(FEATURES_PATH)
        _scaler = joblib.load(SCALER_PATH)
 
 
class PredictRequest(BaseModel):
    url: str
 
 
class PredictResponse(BaseModel):
    url: str
    is_phishing: bool
    phishing_probability: float
    risk_level: str
    trust_override_applied: bool = False
 
 
# Trust override now covers subdomains of trusted domains too (e.g.
# students.masaischool.com is trusted because masaischool.com is), since
# for an institution's own site, subdomains are under the same owner's
# control — the false-positive cost of NOT trusting them outweighs the
# risk for most real-world sites.
#
# The one place this reasoning breaks down is free-hosting / user-generated
# subdomain platforms, where literally anyone can register
# "anything.platform.com" — trusting those blanket would defeat the whole
# point of a reputation check. Those apex domains are excluded from the
# override entirely, subdomain or not, so they're always scored purely
# on their URL features.
UGC_SUBDOMAIN_PLATFORMS = {
    "github.io", "blogspot.com", "wordpress.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "herokuapp.com", "netlify.app",
    "vercel.app", "pages.dev", "firebaseapp.com", "web.app",
    "googleusercontent.com", "sites.google.com", "notion.site",
    "glitch.me", "repl.co", "surge.sh", "azurewebsites.net",
}
 
TRUST_OVERRIDE_CAP = 0.05
 
 
def _apply_trust_override(proba: float, features: dict, full_domain: str) -> tuple[float, bool]:
    if full_domain in UGC_SUBDOMAIN_PLATFORMS:
        return proba, False  # never override — subdomains here are unowned
    if full_domain in SHORTENER_DOMAINS:
        # Popular (so on the trusted list) but the destination is anyone's —
        # a trusted verdict for bit.ly says nothing about where it leads.
        return proba, False
 
    is_reputable = features.get("is_trusted_domain") == 1
    is_restricted = features.get("is_restricted_tld") == 1
 
    if (is_reputable or is_restricted) and features.get("has_ip_address") == 0:
        return min(proba, TRUST_OVERRIDE_CAP), True
    return proba, False
 
 
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/app/")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}
 
 
def score_url(url: str) -> PredictResponse:
    try:
        _load_artifacts()
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Run train_model.py first.",
        )
 
    features = extract_features(url)
    row = pd.DataFrame([features])[_feature_cols]
    row_scaled = _scaler.transform(row)
 
    proba = float(_model.predict_proba(row_scaled)[0, 1])
    full_domain = get_full_domain(url)
    proba, override_applied = _apply_trust_override(proba, features, full_domain)
    is_phishing = proba >= 0.5
 
    if proba >= 0.75:
        risk = "high"
    elif proba >= 0.5:
        risk = "medium"
    elif proba >= 0.25:
        risk = "low"
    else:
        risk = "safe"
 
    return PredictResponse(
        url=url,
        is_phishing=is_phishing,
        phishing_probability=round(proba, 4),
        risk_level=risk,
        trust_override_applied=override_applied,
    )


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    return score_url(req.url)


MAX_EMAIL_CHARS = 10_000_000  # ~10 MB; real phishing samples are far smaller


class EmailRequest(BaseModel):
    raw: str


@app.post("/analyze/email")
def analyze_email_endpoint(req: EmailRequest):
    if not req.raw.strip():
        raise HTTPException(status_code=400, detail="Email is empty.")
    if len(req.raw) > MAX_EMAIL_CHARS:
        raise HTTPException(status_code=413, detail="Email too large (max ~10 MB).")
    return analyze_email(req.raw)


# ─── Enrichment (no keys needed; VirusTotal / URLhaus only if configured) ──

class DomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class IpRequest(BaseModel):
    ip: str


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


@app.post("/enrich/domain")
def enrich_domain(req: DomainRequest):
    domain = req.domain.strip().lower().rstrip(".")
    return {"domain": domain, "rdap": intel.rdap_domain(domain), "dns": intel.dns_records(domain)}


@app.post("/enrich/ip")
def enrich_ip(req: IpRequest):
    try:
        addr = ipaddress.ip_address(req.ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP address.")
    if addr.version != 4:
        raise HTTPException(status_code=400, detail="Only IPv4 is supported for now.")
    if not addr.is_global:
        return {"ip": str(addr), "private": True}
    return intel.ip_info(str(addr))


@app.post("/enrich/url")
def enrich_url(req: UrlRequest):
    url = req.url.strip()
    return {
        "url": url,
        "ml": score_url(url),
        "blocklists": intel.blocklist_check(url),
        "urlhaus": intel.urlhaus_lookup(url),
        "virustotal": intel.virustotal_lookup(url),
    }


# ─── AI summaries (template / Ollama / Gemini) ───────────────────────────

class SummaryRequest(BaseModel):
    kind: Literal["headers", "urls", "iocs", "infra", "executive"]
    case: dict
    provider: Literal["template", "ollama", "gemini"] = "template"
    redact: bool = True
    # Return the exact prompt instead of calling the provider, so the user
    # can review what would leave the machine before sending it.
    dry_run: bool = False


@app.post("/ai/summarize")
def ai_summarize(req: SummaryRequest):
    if req.dry_run:
        return {"provider": req.provider, "redacted": req.redact,
                "system": ai.SYSTEM_PROMPT, "prompt": ai.build_prompt(req.kind, req.case, req.redact)}
    try:
        return ai.summarize(req.kind, req.case, req.provider, req.redact)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:  # network errors from the provider
        raise HTTPException(status_code=502, detail=f"{req.provider} request failed: {e.__class__.__name__}")


@app.get("/config")
def config():
    return {"ai": ai.providers_status(), "intel": intel.intel_status()}
