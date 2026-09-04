from pathlib import Path
from datetime import datetime, timezone
import html
import json
import tempfile


def create_report(data):
    risk = data.get("risk", {})
    rows = "".join(f"<li>{html.escape(x)}</li>" for x in risk.get("reasons", []))
    urls = "".join(
        f"<li>{html.escape(x.get('url', ''))} — {html.escape(', '.join(x.get('flags', [])) or 'No flags')}</li>"
        for x in data.get("threat_intelligence", {}).get("urls", [])
    )
    ips = "".join(
        f"<li>{html.escape(x.get('ip', ''))} — {html.escape(x.get('type', ''))}"
        f"{' (' + html.escape(x['reverse_dns']) + ')' if x.get('reverse_dns') else ''}</li>"
        for x in data.get("threat_intelligence", {}).get("ips", [])
    )
    atts = "".join(
        f"<li>{html.escape(a.get('filename', ''))} ({html.escape(a.get('content_type', ''))})"
        f"{' — ⚠ suspicious extension' if a.get('suspicious_extension') else ''}</li>"
        for a in data.get("attachments", [])
    )
    generated = datetime.now(timezone.utc).isoformat()

    level = (risk.get("level") or "UNKNOWN").upper()
    level_colors = {
        "LOW": "#2FD9C4", "MEDIUM": "#F2A93B", "HIGH": "#FF7A45",
        "CRITICAL": "#FF3B5C", "UNKNOWN": "#93A2B4",
    }
    level_color = level_colors.get(level, "#93A2B4")

    content = f"""<!doctype html><html><head><meta charset='utf-8'>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email Forensic Report</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{font-family:'IBM Plex Mono',SFMono-Regular,Consolas,monospace;max-width:860px;margin:0 auto;
  padding:48px 28px 64px;line-height:1.6;color:#E7ECF3;background:#0A0E14}}
h1{{font-size:22px;margin:0 0 4px;font-weight:700;letter-spacing:-.01em}}
h2{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#5C6B7E;
  border-bottom:1px solid #212B38;padding-bottom:8px;margin:34px 0 14px}}
.meta{{color:#5C6B7E;font-size:12.5px;margin-bottom:26px}}
.risk-band{{display:flex;align-items:center;gap:16px;background:#10161F;border:1px solid #212B38;
  border-radius:12px;padding:18px 22px;margin-bottom:8px}}
.risk-score{{font-size:34px;font-weight:700}}
.risk-level{{font-size:12px;font-weight:700;letter-spacing:.04em;padding:5px 12px;border-radius:20px;
  color:{level_color};background:{level_color}1a;border:1px solid {level_color}55}}
p{{margin:6px 0;font-size:13.5px}}
ul{{margin:0;padding-left:18px;font-size:13.5px}}
li{{margin:5px 0}}
pre{{white-space:pre-wrap;word-break:break-word;background:#0B1119;border:1px solid #212B38;
  padding:14px;border-radius:8px;font-size:12px;color:#93A2B4}}
b{{color:#93A2B4;font-weight:600}}
.footer-note{{margin-top:40px;color:#5C6B7E;font-size:11.5px}}
</style></head>
<body>
<h1>Email Threat &amp; Forensic Report</h1>
<p class='meta'>MailSentinel · generated {html.escape(generated)}Z</p>
<div class='risk-band'>
  <div class='risk-score'>{risk.get('score', 0)}<span style="font-size:16px;color:#5C6B7E">/100</span></div>
  <div class='risk-level'>{html.escape(level)}</div>
</div>
<h2>Message</h2>
<p><b>From</b> &nbsp;{html.escape(data.get('sender', ''))}</p>
<p><b>Reply-To</b> &nbsp;{html.escape(data.get('reply_to', ''))}</p>
<p><b>Subject</b> &nbsp;{html.escape(data.get('subject', ''))}</p>
<p><b>Date</b> &nbsp;{html.escape(data.get('date', ''))}</p>
<p><b>SHA-256</b> &nbsp;{html.escape(data.get('sha256', ''))}</p>
<h2>Risk reasons</h2><ul>{rows or '<li>No major risk reason recorded.</li>'}</ul>
<h2>URLs</h2><ul>{urls or '<li>None</li>'}</ul>
<h2>IP addresses</h2><ul>{ips or '<li>None</li>'}</ul>
<h2>Attachments</h2><ul>{atts or '<li>None</li>'}</ul>
<h2>Authentication</h2><pre>{html.escape(json.dumps(data.get('authentication', {}), indent=2))}</pre>
<h2>AI baseline assessment</h2><pre>{html.escape(json.dumps(data.get('ml', {}), indent=2))}</pre>
<h2>Body</h2><pre>{html.escape(data.get('body', ''))}</pre>
<p class='footer-note'>Heuristic detection baseline generated for demonstration and academic evaluation — not a substitute for a production email security stack.</p>
</body></html>"""

    # Write to a temp dir rather than the working directory so concurrent
    # requests don't clobber each other's report file.
    out_dir = Path(tempfile.gettempdir())
    path = out_dir / "email-forensic-report.html"
    path.write_text(content, encoding="utf-8")
    return str(path)
