"""
MITRE ATT&CK mapping for PhishIntel findings.

Technique IDs checked against attack.mitre.org (Enterprise, ATT&CK v20,
October 2026). Note: v20 moved Impersonation and Email Spoofing under the
new T1684 Social Engineering (the older T1656 / T1672 are revoked), so
reports should cite T1684.001 / T1684.002.

ATT&CK has no dedicated technique for QR-code phishing ("quishing"); it is
mapped as Spearphishing Link + User Execution: Malicious Link.
"""

TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.002": "Phishing for Information: Spearphishing Attachment",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1684.001": "Social Engineering: Impersonation",
    "T1684.002": "Social Engineering: Email Spoofing",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.007": "Masquerading: Double File Extension",
    "T1027": "Obfuscated Files or Information",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1608.005": "Stage Capabilities: Link Target",
}

# finding title -> techniques it is evidence of
BY_TITLE = {
    # sender / authentication
    "SPF fail": ["T1684.002"],
    "SPF softfail": ["T1684.002"],
    "DKIM fail": ["T1684.002"],
    "DMARC fail": ["T1684.002"],
    "Display-name spoofing": ["T1684.002", "T1684.001"],
    "Email address hidden in display name": ["T1684.002", "T1684.001"],
    "Sender domain imitates a brand": ["T1684.001", "T1583.001"],
    # links
    "Link domain imitates a brand": ["T1684.001", "T1583.001", "T1566.002"],
    "Link text shows a different site than the real target": ["T1566.002", "T1204.001"],
    "Link points to a raw IP address": ["T1566.002", "T1204.001"],
    "Punycode / IDN domain (possible homoglyph lookalike)": ["T1684.001", "T1583.001"],
    "URL uses '@' to disguise the real host": ["T1566.002", "T1204.001"],
    "Link uses a URL shortener (hides the destination)": ["T1566.002", "T1608.005"],
    "HTML form submits data to an external site": ["T1598.003"],
    "QR code in the email links to a website": ["T1566.002", "T1204.001"],
    # attachments
    "Risky attachment type": ["T1566.001", "T1204.002"],
    "Double file extension": ["T1036.007", "T1566.001", "T1204.002"],
    "Archive attachment (can hide malware)": ["T1566.001"],
    "HTML attachment contains a credential form": ["T1598.002"],
    "HTML attachment redirects to an external site": ["T1566.001", "T1204.002"],
    "Obfuscated script in HTML attachment": ["T1027"],
    # enrichment findings (added by the PhishIntel UI)
    "Newly registered domain": ["T1583.001"],
    "Recently registered domain": ["T1583.001"],
    "URL is on a phishing blocklist": ["T1566.002"],
}


def url_for(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def annotate(findings: list) -> list:
    """Adds an `attack` list of technique IDs to each finding, in place."""
    for f in findings:
        f["attack"] = BY_TITLE.get(f["title"], [])
    return findings


def summary(findings: list) -> list:
    """Unique techniques, most-evidenced first, with the findings behind each."""
    techniques = {}
    for f in findings:
        for tid in f.get("attack", []):
            t = techniques.setdefault(tid, {"id": tid, "name": TECHNIQUES[tid], "url": url_for(tid),
                                            "evidence": []})
            if f["title"] not in t["evidence"]:
                t["evidence"].append(f["title"])
    return sorted(techniques.values(), key=lambda t: (-len(t["evidence"]), t["id"]))
