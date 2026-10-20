"""
Per-prediction explanations: *why* did the model score this URL as it did?

Method: occlusion against a reference. For each feature whose value differs
from the typical legitimate URL (the median of the legit training rows), we
re-score the URL with just that feature set to the reference value. The drop
in phishing probability is that feature's contribution. It is model-agnostic,
needs no extra libraries (no SHAP), and costs one batched predict call.
"""

import numpy as np
import pandas as pd

# feature -> function(value) returning a human-readable reason
REASON_TEXT = {
    "url_length": lambda v: f"Very long URL ({int(v)} characters)",
    "domain_length": lambda v: f"Unusually long domain name ({int(v)} characters)",
    "path_length": lambda v: f"Long path ({int(v)} characters)",
    "num_dots": lambda v: f"Many dots in the URL ({int(v)})",
    "num_hyphens": lambda v: f"Hyphens in the URL ({int(v)})",
    "num_underscores": lambda v: f"Underscores in the URL ({int(v)})",
    "num_at_symbols": lambda v: "Contains '@', which can hide the real destination",
    "num_digits": lambda v: f"Digits in the URL ({int(v)})",
    "num_subdomains": lambda v: (f"Extra subdomain in front of the real domain" if v == 1
                                 else f"{int(v)} subdomain levels in front of the real domain"),
    "has_ip_address": lambda v: "Uses a raw IP address instead of a domain name",
    "uses_https": lambda v: "Not using HTTPS" if v == 0 else "Uses HTTPS",
    "has_suspicious_word": lambda v: "Contains login/verify/account-style keywords",
    "is_shortened": lambda v: "URL shortener / QR redirector hides the destination",
    "num_query_params": lambda v: f"Many query parameters ({int(v)})",
    "domain_entropy": lambda v: f"Random-looking domain name (entropy {v:.2f})",
    "digit_ratio": lambda v: f"High share of digits ({v:.0%})",
    "is_punycode": lambda v: "Internationalised (punycode) domain — possible look-alike characters",
    "brand_in_subdomain": lambda v: "Brand name used in a subdomain of an unrelated site",
    "brand_in_path": lambda v: "Brand name appears in the path of an unrelated site",
    "brand_edit_distance": lambda v: ("Domain contains a brand name it doesn't belong to" if v == 0
                                      else f"Domain is {int(v)} character(s) away from a brand name"),
    "is_typosquat": lambda v: "Domain looks like a misspelt brand (typosquatting)",
    "is_free_hosting": lambda v: "Hosted on a free website platform where anyone can publish",
    "suspicious_tld": lambda v: "Uses a top-level domain frequently abused for phishing",
    "subdomain_length": lambda v: f"Long subdomain ({int(v)} characters)",
    "domain_hyphens": lambda v: ("Hyphen in the domain name" if v == 1
                                 else f"{int(v)} hyphens in the domain name"),
    "domain_digits": lambda v: f"Digits in the domain name ({int(v)})",
    "domain_vowel_ratio": lambda v: "Domain name has an unusual letter pattern",
    "path_depth": lambda v: f"Deeply nested path ({int(v)} levels)",
    "has_file_extension": lambda v: "Points directly at a script/page file (.php, .html…)",
    "query_length": lambda v: f"Long query string ({int(v)} characters)",
    "has_embedded_url": lambda v: "Contains another URL inside it (redirect)",
    "longest_token": lambda v: f"Contains a very long random-looking token ({int(v)} characters)",
    "url_entropy": lambda v: f"Random-looking URL (entropy {v:.2f})",
}

# Features where a LOW value is the suspicious direction. For every other
# feature the reason texts describe "more than usual", so a contribution from
# a below-typical value (e.g. a shorter-than-usual subdomain) isn't a reason
# a person would recognise and is skipped.
LOW_IS_SUSPICIOUS = {"uses_https", "brand_edit_distance", "domain_vowel_ratio"}

IP_RESTATED_FEATURES = {"has_ip_address", "domain_digits", "digit_ratio", "num_digits",
                        "domain_length", "domain_entropy", "domain_vowel_ratio", "num_dots"}

# Measured in log-odds: near 100% a single feature barely moves the
# probability (0.999 -> 0.995) but clearly moves the odds.
MIN_LOGIT_CONTRIBUTION = 0.3


def _logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def explain(model, features: list, reference: dict, row: dict, proba: float, top_n: int = 3) -> list:
    """Top features pushing this URL towards 'phishing', as readable reasons."""
    def suspicious_direction(f):
        v, ref = row[f], reference.get(f)
        return v < ref if f in LOW_IS_SUSPICIOUS else v > ref

    # For a raw-IP host the "domain" features just restate the IP's digits
    # (8 digits, 27% digits…) — the reason a person understands is the IP itself.
    ip_host = row.get("has_ip_address") == 1
    skip = IP_RESTATED_FEATURES if ip_host else set()
    changed = [f for f in features
               if f not in skip and row[f] != reference.get(f) and suspicious_direction(f)]
    lead = [{"feature": "has_ip_address", "value": 1, "contribution": None,
             "reason": REASON_TEXT["has_ip_address"](1)}] if ip_host else []
    top_n -= len(lead)
    if not changed or top_n <= 0:
        return lead
    base = pd.DataFrame([row])[features].astype(float)  # int columns can't take median values
    variants = pd.concat([base] * len(changed), ignore_index=True)
    for i, f in enumerate(changed):
        variants.at[i, f] = reference[f]
    deltas = _logit(proba) - _logit(model.predict_proba(variants)[:, 1])
    order = np.argsort(-deltas)
    reasons = []
    for i in order[:top_n]:
        if deltas[i] < MIN_LOGIT_CONTRIBUTION:
            break
        f = changed[i]
        text = REASON_TEXT.get(f, lambda v, f=f: f"{f} = {v}")(row[f])
        reasons.append({"feature": f, "value": row[f], "contribution": round(float(deltas[i]), 2),
                        "reason": text})
    return lead + reasons
