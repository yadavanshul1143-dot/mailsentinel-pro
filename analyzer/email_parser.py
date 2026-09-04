import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser

PHRASES = [
    "urgent", "verify your account", "password", "login", "click here", "account suspended",
    "account locked", "confirm your account", "reset password", "limited time",
    "security alert", "payment required", "wire transfer", "gift card", "invoice",
    "update your account", "verify immediately", "unusual activity", "suspend your account",
    "act now", "your account will be closed", "confirm your identity", "one time password",
    "otp code", "click the link below", "final notice", "failure to comply",
]
SUSPICIOUS_ATTACHMENT_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1", ".msi",
    ".hta", ".wsf", ".lnk", ".iso", ".dll",
}
IP_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
URL_RE = r"https?://[^\s<>\"'\)]+"


class _TextExtractor(HTMLParser):
    """Very small fallback HTML->text stripper, used only when a message has
    no text/plain part. Not a full renderer; good enough to feed the phrase
    and URL heuristics."""

    def __init__(self):
        super().__init__()
        self._chunks = []

    def handle_data(self, data):
        self._chunks.append(data)

    def text(self):
        return " ".join(self._chunks)


def _html_to_text(html_str):
    parser = _TextExtractor()
    try:
        parser.feed(html_str)
    except Exception:
        return html_str
    return parser.text()


def body_text(msg):
    """Prefer text/plain; fall back to a stripped text/html part if that's
    all the message has, so phrase/URL detection still works on HTML-only
    phishing emails."""
    if msg.is_multipart():
        plain_parts = []
        html_parts = []
        for p in msg.walk():
            disp = (p.get("Content-Disposition") or "").lower()
            if disp.startswith("attachment"):
                continue
            ctype = p.get_content_type()
            try:
                content = p.get_content()
            except Exception:
                continue
            if ctype == "text/plain":
                plain_parts.append(content)
            elif ctype == "text/html":
                html_parts.append(content)
        if plain_parts:
            return "\n".join(plain_parts)
        if html_parts:
            return "\n".join(_html_to_text(h) for h in html_parts)
        return ""
    try:
        content = msg.get_content()
    except Exception:
        payload = msg.get_payload(decode=True)
        content = payload.decode(errors="ignore") if payload else ""
    if msg.get_content_type() == "text/html":
        return _html_to_text(content)
    return content


def attachments(msg):
    found = []
    if not msg.is_multipart():
        return found
    for p in msg.walk():
        disp = (p.get("Content-Disposition") or "").lower()
        filename = p.get_filename()
        if disp.startswith("attachment") or filename:
            name = filename or "(unnamed attachment)"
            ext = ""
            if "." in name:
                ext = "." + name.rsplit(".", 1)[-1].lower()
            found.append({
                "filename": name,
                "content_type": p.get_content_type(),
                "suspicious_extension": ext in SUSPICIOUS_ATTACHMENT_EXT,
            })
    return found


def _domain(addr):
    _, email_addr = parseaddr(addr or "")
    m = re.search(r"@([A-Za-z0-9.-]+)", email_addr or "")
    return m.group(1).lower() if m else ""


def parse_email(raw):
    msg = Parser(policy=policy.default).parsestr(raw)
    body = body_text(msg)
    sender = msg.get("From", "")
    reply = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    text = (subject + " " + body).lower()
    indicators = [f"Suspicious phrase: {p}" for p in PHRASES if p in text]

    sd, rd = _domain(sender), _domain(reply)
    if sd and rd and sd != rd:
        indicators.append(f"From/Reply-To domain mismatch: {sd} -> {rd}")

    # Detect a display name that looks like a different, more trustworthy domain
    # than the actual sending address (a common brand-impersonation pattern).
    display_name, sender_addr = parseaddr(sender or "")
    if display_name:
        name_domains = re.findall(r"([a-z0-9-]+\.(?:com|net|org|co|io))", display_name.lower())
        if name_domains and sd and all(nd != sd for nd in name_domains):
            indicators.append(f"Display name references '{name_domains[0]}' but sender domain is '{sd}'")

    urls = []
    for u in re.findall(URL_RE, raw):
        urls.append(u.rstrip(".,);]"))
    ips = list(dict.fromkeys(re.findall(IP_RE, raw)))
    auth = {k: msg.get(k, "") for k in ["Authentication-Results", "Received-SPF", "DKIM-Signature"] if msg.get(k)}
    atts = attachments(msg)
    if any(a["suspicious_extension"] for a in atts):
        bad = ", ".join(a["filename"] for a in atts if a["suspicious_extension"])
        indicators.append(f"Suspicious attachment type(s): {bad}")

    all_recipients = [a for _, a in getaddresses([msg.get("To", ""), msg.get("Cc", "")]) if a]

    return {
        "sender": sender, "reply_to": reply, "subject": subject, "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""), "body": body[:30000],
        "recipients": all_recipients[:50],
        "urls": list(dict.fromkeys(urls))[:100], "ips": ips[:100],
        "attachments": atts[:50],
        "indicators": indicators, "authentication_headers": auth,
    }
