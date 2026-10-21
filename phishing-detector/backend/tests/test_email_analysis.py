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


# ─── Phase 3: QR codes, HTML attachments, ATT&CK ─────────────────────────

import attack


def test_quishing_qr_code_decoded():
    r = load("quishing.eml")
    assert r["qr_codes"][0]["text"] == "https://m1crosoft-mfa-reset.com/auth/verify?uid=8f2c91d0"
    qr_url = next(u for u in r["urls"] if u["source"] == "qr-code")
    assert qr_url["found_in"] == "mfa-qr@contoso"
    assert "brand-lookalike:microsoft" in qr_url["flags"]
    assert "QR code in the email links to a website" in titles(r)
    assert r["verdict"]["level"] == "high"


def test_html_attachment_redirect_and_obfuscation():
    r = load("voicemail.eml")
    s = r["html_attachments"][0]
    assert s["filename"] == "VM_0812_Play.html" and s["redirects"] == 1 and s["obfuscated"]
    assert {"HTML attachment redirects to an external site",
            "Obfuscated script in HTML attachment"} <= titles(r)
    assert any(u["source"] == "attachment-redirect" and "vm-portal-login.top" in u["url"] for u in r["urls"])


def test_html_attachment_form_in_bank_sample():
    r = load("bank-kyc.eml")
    assert "HTML attachment contains a credential form" in titles(r)
    assert any(u["source"] == "attachment-form" and u["url"] == "https://hdfc-kyc-update.in/submit"
               for u in r["urls"])


def test_leet_one_as_i():
    assert _brand_lookalike("m1crosoft-mfa-reset.com") == "microsoft"


def test_attack_mapping_uses_current_ids():
    r = load("bank-kyc.eml")
    ids = {t["id"] for t in r["attack"]}
    assert {"T1684.001", "T1036.007", "T1598.002"} <= ids
    # v20 revoked T1656 / T1672 in favour of T1684.001 / T1684.002
    assert not ids & {"T1656", "T1672"}
    for t in r["attack"]:
        assert t["url"] == "https://attack.mitre.org/techniques/" + t["id"].replace(".", "/") + "/"
        assert t["evidence"]
    # every mapped title points at a known technique
    assert all(tid in attack.TECHNIQUES for ids_ in attack.BY_TITLE.values() for tid in ids_)


def test_legit_sample_has_no_attack_techniques():
    assert load("legit-newsletter.eml")["attack"] == []
