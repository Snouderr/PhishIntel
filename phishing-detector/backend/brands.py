"""
Shared reference data for URL features and email analysis: impersonated
brands, free-hosting platforms and abused TLDs. Pure data + tiny helpers,
no imports from the rest of the backend (avoids circular imports).
"""

# Brand keyword -> registered domains that brand actually owns / sends from.
# A brand keyword in a domain that ISN'T in its list is a lookalike signal
# (docusign-secure.com, paypal-verify.net).
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com",
                  "microsoftonline.com", "office365.com"},
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "google.co.in",
               "googleusercontent.com", "withgoogle.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "whatsapp": {"whatsapp.com"},
    "hdfc": {"hdfcbank.com", "hdfc.bank.in"},
    "icici": {"icicibank.com", "icici.bank.in"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "usps": {"usps.com"},
}

ALL_BRAND_DOMAINS = set().union(*BRAND_DOMAINS.values())

# Brands that are also common words or word fragments (purchase, mainstream,
# pineapple) — only match these as a whole token, never as a substring.
TOKEN_ONLY_BRANDS = {"chase", "steam", "apple", "adobe", "usps", "dhl", "sbi", "hdfc"}


def brand_matches(brand: str, text: str, tokens: set) -> bool:
    if brand in TOKEN_ONLY_BRANDS or len(brand) <= 4:
        return brand in tokens
    return brand in text

# Platforms where anyone can publish under a subdomain/path of a reputable
# domain — reputation of the platform says nothing about one page on it.
FREE_HOSTING_PLATFORMS = {
    "github.io", "blogspot.com", "wordpress.com", "weebly.com", "weeblysite.com",
    "wixsite.com", "wixstudio.com", "000webhostapp.com", "herokuapp.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "firebaseapp.com",
    "web.app", "googleusercontent.com", "sites.google.com", "notion.site",
    "glitch.me", "repl.co", "replit.app", "surge.sh", "azurewebsites.net",
    "webflow.io", "gitlab.io", "square.site", "carrd.co", "framer.app",
    "godaddysites.com", "mystrikingly.com", "jimdosite.com", "ipfs.io",
    "dweb.link", "duckdns.org", "ngrok.io", "ngrok-free.app", "r2.dev",
}

# TLDs that recurring abuse reports (Spamhaus, Interisle) list as having a
# high share of phishing / malicious registrations. A weak signal on its own.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz", "cfd", "sbs",
    "click", "rest", "cyou", "monster", "quest", "lol", "bond", "zip", "mov",
    "support", "help", "live", "online", "site", "shop", "store", "info",
    "work", "fit", "loan", "win", "bid", "vip", "pw", "cc", "su",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """Edit distance, early-exiting once it exceeds max_dist."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]
