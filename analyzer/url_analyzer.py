from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorte.st", "rb.gy",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "quest",
}
BRAND_KEYWORDS = [
    "paypal", "microsoft", "apple", "amazon", "google", "netflix", "bankofamerica",
    "wellsfargo", "chase", "irs", "office365", "outlook",
]


def _looks_typosquat(host):
    """Flag when a well-known brand name appears in the hostname but the
    hostname is not that brand's real registrable domain — a cheap signal
    for lookalike domains like 'paypal-secure-login.com'."""
    for brand in BRAND_KEYWORDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            return brand
    return None


def analyze_urls(urls):
    out = []
    for u in urls:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        flags = []
        if host.replace(".", "").isdigit():
            flags.append("IP-address host")
        if host in SHORTENERS:
            flags.append("URL shortener")
        if "@" in u:
            flags.append("@ symbol in URL")
        if any(x in (p.path + "?" + p.query).lower() for x in
               ["login", "verify", "password", "secure", "account", "confirm", "update"]):
            flags.append("credential/action keyword")
        if p.scheme != "https":
            flags.append("not HTTPS")
        if len(host.split(".")) >= 5:
            flags.append("deep subdomain")
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("punycode/internationalized domain (possible homograph)")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"suspicious top-level domain (.{tld})")
        if len(u) > 120:
            flags.append("unusually long URL")
        brand = _looks_typosquat(host)
        if brand:
            flags.append(f"possible '{brand}' lookalike domain")
        out.append({"url": u, "host": host, "flags": flags, "suspicious": bool(flags)})
    return out
