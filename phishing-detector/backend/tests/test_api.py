import api


def predict(client, url):
    r = client.post("/predict", json={"url": url})
    assert r.status_code == 200, r.text
    return r.json()


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["model_loaded"] is True


def test_predict_response_shape(client):
    body = predict(client, "http://paypal-secure-login.tk/verify/account?id=283991")
    assert set(body) == {
        "url", "is_phishing", "phishing_probability", "risk_level", "trust_override_applied",
        "reasons", "model_version",
    }
    assert 0 <= body["phishing_probability"] <= 1
    assert body["risk_level"] in {"safe", "low", "medium", "high"}


def test_trusted_domain_is_capped(client):
    body = predict(client, "https://www.google.com/search?q=test")
    assert body["trust_override_applied"] is True
    assert body["phishing_probability"] <= api.TRUST_OVERRIDE_CAP


def test_ugc_platform_never_overridden(client):
    body = predict(client, "https://secure-login-update.github.io/paypal/")
    assert body["trust_override_applied"] is False


def test_shortener_never_overridden(client):
    assert predict(client, "https://bit.ly/3xPhsh")["trust_override_applied"] is False


def test_restricted_tld_override(client):
    assert predict(client, "https://somebank.bank.in/login")["trust_override_applied"] is True


def test_missing_url_is_422(client):
    assert client.post("/predict", json={}).status_code == 422


def test_root_redirects_to_phishintel(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/app/"
    assert "PhishIntel" in client.get("/app/").text


# ─── v2 model behaviour ──────────────────────────────────────────────────

def test_v2_model_loaded(client):
    assert client.get("/health").json()["model_version"] == "2.0"


def test_typosquat_rule_floors_to_high(client):
    body = predict(client, "https://steamcommunlty-gift.ru/redirect")
    assert body["risk_level"] == "high"
    assert body["reasons"][0]["feature"] == "rule:brand_impersonation"


def test_brand_subdomain_rule(client):
    body = predict(client, "https://paypal.account-verify.xyz/")
    assert body["is_phishing"] and "subdomain" in body["reasons"][0]["reason"]


def test_shortener_reported_as_medium(client):
    body = predict(client, "https://bit.ly/3xPhsh")
    assert body["risk_level"] == "medium"
    assert body["reasons"][0]["feature"] == "rule:shortener"


def test_legit_deep_links_are_safe(client):
    for url in ("https://github.com/anthropics/claude-code/issues/123",
                "https://www.bbc.co.uk/sport/football",
                "https://docs.python.org/3/library/email.html"):
        body = predict(client, url)
        assert not body["is_phishing"], url
        assert body["reasons"] == []


def test_reasons_are_readable(client):
    body = predict(client, "http://paypa1-secure.com/login.php?x=1")
    assert body["risk_level"] == "high"
    assert 1 <= len(body["reasons"]) <= 3
    assert all(r["reason"] and "=" not in r["reason"] for r in body["reasons"])


def test_ip_url_has_no_subdomain_reason(client):
    body = predict(client, "http://192.168.1.1/banking/confirm")
    assert body["is_phishing"]
    assert body["reasons"][0]["feature"] == "has_ip_address"
    assert not any("subdomain" in r["reason"] or "digit" in r["reason"].lower() for r in body["reasons"])
