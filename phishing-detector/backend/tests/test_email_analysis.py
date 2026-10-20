import os

import pytest

from email_analysis import _brand_lookalike, analyze_email, refang

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "..", "phishintel", "samples")


def load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return analyze_email(f.read())


def titles(result):
    return {f["title"] for f in result["findings"]}


def ioc_values(result, type_=None):
    return {i["indicator"] for i in result["iocs"] if type_ in (None, i["type"])}


def test_docusign_sample():
    r = load("docusign.eml")
    assert r["verdict"]["level"] == "high"
    assert r["auth"]["spf"] == "fail" and r["auth"]["dmarc"] == "fail"
    assert r["auth"]["spam_flagged"] and r["auth"]["spam_score"] == 8.4
    assert {"Display-name spoofing", "Sender domain imitates a brand",
            "Link text shows a different site than the real target"} <= titles(r)
    # Origin is the external hop, not the internal relay
    assert ioc_values(r, "IP") == {"185.199.108.153"}
    # The decoy link text (real docusign.com) is not an IOC, nor is bit.ly as a domain
    assert "docusign.com" not in ioc_values(r, "Domain")
    assert "bit.ly" not in ioc_values(r, "Domain")
    assert "https://bit.ly/3xPhsh" in ioc_values(r, "URL")


def test_microsoft_sample_quoted_printable_and_defanged():
    r = load("microsoft365.eml")
    urls = {u["url"] for u in r["urls"]}
    # quoted-printable '=3D' decoded, defanged text URL merged with the HTML one
    assert "https://login-microsoftonline.account-verify.xyz/owa/?user=j.doe" in urls
    assert "http://45.133.1.77/collect.php" in urls
    assert {"Email address hidden in display name", "HTML form submits data to an external site",
            "Link points to a raw IP address", "Link domain imitates a brand"} <= titles(r)
    assert r["verdict"]["level"] == "high"


def test_bank_sample_attachment_and_reply_to():
    r = load("bank-kyc.eml")
    assert r["auth"]["spf"] == "pass"  # passing SPF doesn't make it safe
    assert r["attachments"][0]["filename"] == "KYC_Form.pdf.html"
    assert len(r["attachments"][0]["sha256"]) == 64
    assert {"Double file extension", "Reply-To domain differs from From"} <= titles(r)
    assert "hdfc.kyc.desk@gmail.com" in ioc_values(r, "Email")
    assert r["verdict"]["level"] == "high"


def test_legit_sample_is_low():
    r = load("legit-newsletter.eml")
    assert r["verdict"]["level"] == "low"
    assert all(f["severity"] == "info" for f in r["findings"])
    assert all(i["severity"] == "low" for i in r["iocs"])


def test_headerless_text_still_extracts_urls():
    r = analyze_email("Please log in at hxxp://evil-login[.]com/verify now")
    assert [u["url"] for u in r["urls"]] == ["http://evil-login.com/verify"]


def test_refang():
    assert refang("hxxps://a[.]b(.)com[:]80") == "https://a.b.com:80"


@pytest.mark.parametrize("domain,brand", [
    ("docusign-secure.com", "docusign"),
    ("micros0ft-365-auth.com", "microsoft"),
    ("paypal.verify-acct.com", "paypal"),
    ("sbi-rewards.in", "sbi"),
    ("paypal.com", None),
    ("accounts.google.com", None),
    ("fsbinsurance.com", None),   # 'sbi' inside an unrelated word
    ("example.org", None),
])
def test_brand_lookalike(domain, brand):
    assert _brand_lookalike(domain) == brand


def test_analyze_endpoint(client):
    r = client.post("/analyze/email", json={"raw": "From: a@b.com\n\nhi http://x.com"})
    assert r.status_code == 200
    assert r.json()["headers"]["from_address"] == "a@b.com"
    assert client.post("/analyze/email", json={"raw": "   "}).status_code == 400
