# MailSentinel — AI Email Threat Intelligence Platform

A deployable Flask cybersecurity project for SIH-style email threat detection and forensic analysis.

## What's new in this design upgrade
- **Redesigned console UI**: a dark, forensic-console interface (`templates/index.html`,
  `static/style.css`, `static/script.js`) built around the app's real pipeline — a
  status bar, a "how it scores" pipeline strip (Parse → Identity → URL/IP intel →
  Auth → Risk score), a two-panel analyze console, a live risk gauge, SPF/DKIM/DMARC
  chips, and a SIEM-style analysis log. No backend logic was changed — same routes,
  same JSON contract, same SQLite storage.
- **One-click sample load**: a "Load sample .eml" button in the console pulls in the
  bundled spoofed/failing-auth phishing sample for live demos.
- **Matching forensic report**: the downloadable HTML report (`analyzer/report.py`)
  now uses the same dark, monospace forensic styling as the console.

## What's new in the previous upgrade
- **Fixed a project-structure bug**: `app.py` imports `analyzer.*`, and Flask's
  `render_template`/`static` need `templates/` and `static/` folders — the
  previous flat layout would have failed to run. Files are now organized as
  a proper `analyzer/` package with `templates/` and `static/` folders.
- **Parsing**: robust `From`/`Reply-To` address parsing (`email.utils`), HTML-only
  email fallback text extraction, attachment detection with a suspicious-extension
  check, and display-name brand-impersonation detection.
- **URL analysis**: added punycode/homograph, suspicious-TLD, overlong-URL, and
  simple brand-lookalike checks alongside the original heuristics.
- **ML baseline**: expanded phrase lists, added urgency-language and
  sensitive-data-keyword scoring, and ALL-CAPS/exclamation subject signals.
- **Risk engine**: extra weight for spoofed sender identity and malicious
  attachments, not just raw indicator counts.
- **API**: paginated `/api/history`, plus new `GET/DELETE /api/history/<id>`
  to view or remove a past analysis; better input validation (file type,
  size caps) and JSON error responses; 413/404 handlers.
- **Report**: writes to a temp directory (safe under concurrent requests),
  timezone-aware timestamps, adds IP/attachment sections.
- **Frontend**: drag-and-drop upload, loading spinner, inline error banner,
  JSON export, and a "View"/"Delete" action on each history entry.

## Features
- `.eml` upload and raw email paste (drag-and-drop supported)
- Header/body parsing, including HTML-only messages
- Explainable NLP phishing baseline
- Sender / Reply-To mismatch and display-name spoofing detection
- URL analysis (shorteners, punycode, suspicious TLDs, lookalike domains)
- IP extraction and reverse DNS
- SPF / DKIM / DMARC result parsing
- Attachment risk flags
- Risk scoring and threat levels
- SHA-256 evidence fingerprint
- SQLite analysis history (view/delete individual entries)
- HTML forensic report + raw JSON export
- Responsive dashboard

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

Try it with the included `sample_suspicious.eml` (SPF/DKIM/DMARC all fail,
mismatched Reply-To, credential-phishing link).

## Deploy on Render
1. Push this project to a GitHub repository.
2. In Render, create a new Web Service from the repository.
3. Render can use `render.yaml`, or set:
   Build: `pip install -r requirements.txt`
   Start: `gunicorn app:app`
4. Deploy.

## Important
The included NLP detector is a self-contained, explainable baseline, not a
trained production model. For a production/SIH final version, train and
validate a classifier on a properly licensed phishing/benign email dataset,
and add authenticated external threat-intelligence providers (VirusTotal,
AbuseIPDB, etc. via environment variables). Do not treat heuristic scores as
definitive evidence.
