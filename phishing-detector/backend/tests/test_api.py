import pytest
from fastapi.testclient import TestClient

import api


@pytest.fixture(scope="module")
def client():
    with TestClient(api.app) as c:
        yield c


def predict(client, url):
    r = client.post("/predict", json={"url": url})
    assert r.status_code == 200, r.text
    return r.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "model_loaded": True}


def test_predict_response_shape(client):
    body = predict(client, "http://paypal-secure-login.tk/verify/account?id=283991")
    assert set(body) == {
        "url", "is_phishing", "phishing_probability", "risk_level", "trust_override_applied",
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


def test_restricted_tld_override(client):
    assert predict(client, "https://somebank.bank.in/login")["trust_override_applied"] is True


def test_missing_url_is_422(client):
    assert client.post("/predict", json={}).status_code == 422


def test_root_redirects_to_phishintel(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/app/"
    assert "PhishIntel" in client.get("/app/").text
