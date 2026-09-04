# 🛡️ MailSentinel Pro

### AI-Assisted Email Threat Intelligence & Phishing Analysis Platform

MailSentinel Pro is a professional cybersecurity web application designed to analyze suspicious emails, identify phishing indicators, inspect sender authenticity, analyze URLs and IP addresses, evaluate email authentication results, and generate an explainable risk assessment.

Built with **Python + Flask**, MailSentinel combines multiple security-analysis techniques into a single forensic-style dashboard designed for cybersecurity learning, demonstrations, SOC-style workflows, and SIH/project presentations.

---

## 🚀 Overview

Email-based attacks remain one of the most common entry points for cyber threats.

MailSentinel Pro provides a centralized workflow for investigating suspicious email messages:

```text
Email Input
     │
     ▼
┌─────────────┐
│ Email Parser│
└──────┬──────┘
       ▼
┌─────────────────┐
│ Identity Checks │
└────────┬────────┘
         ▼
┌─────────────────┐
│ URL / IP Intel  │
└────────┬────────┘
         ▼
┌─────────────────┐
│ SPF / DKIM /    │
│ DMARC Analysis  │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Threat Detection│
└────────┬────────┘
         ▼
┌─────────────────┐
│ Risk Engine     │
└────────┬────────┘
         ▼
   Threat Verdict
```

The result is presented through a modern cybersecurity dashboard with risk visualization, authentication indicators, threat intelligence, forensic details, and analysis history.

---

## ✨ Key Features

### 📧 Email Analysis

* `.eml` and `.txt` email analysis
* Raw email text input
* Drag-and-drop upload
* Email header and body parsing
* HTML-only email fallback extraction
* Sender and Reply-To inspection
* Attachment detection
* Suspicious attachment extension detection

### 🧠 Phishing Detection

MailSentinel uses an explainable NLP-style baseline to identify suspicious language patterns including:

* Urgency indicators
* Credential requests
* Sensitive-data requests
* Phishing terminology
* Suspicious subject patterns
* Excessive capitalization
* Excessive exclamation marks

The system provides interpretable signals rather than treating the detection result as a black box.

### 🕵️ Sender Identity Analysis

Detects suspicious sender behavior such as:

* Sender / Reply-To mismatch
* Display-name impersonation
* Brand-lookalike indicators
* Suspicious sender patterns

### 🔗 URL Intelligence

Analyzes URLs extracted from emails for indicators including:

* URL shorteners
* Punycode / homograph indicators
* Suspicious TLDs
* Overly long URLs
* Lookalike domains
* Potential phishing destinations

### 🌐 IP Analysis

* IP extraction
* IOC enrichment
* Reverse DNS analysis

### 🔐 Email Authentication

Analyzes authentication headers for:

* SPF
* DKIM
* DMARC

Authentication results are incorporated into the overall risk calculation.

### ⚠️ Risk Scoring

MailSentinel combines multiple security signals into an overall risk assessment.

Example threat levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The dashboard provides a visual representation of the calculated risk.

### 🧾 Forensic Evidence

Every analysis can include:

* SHA-256 evidence fingerprint
* Extracted URLs
* Extracted IP addresses
* Authentication results
* Attachments
* Detection indicators
* Threat intelligence
* Timestamp
* Source filename

### 📊 Analysis History

Previous analyses are stored in SQLite.

Supported operations include:

* View previous analysis
* Inspect complete results
* Delete individual records
* Paginated history API

### 📄 Forensic Reports

Generate downloadable HTML forensic reports containing the analysis results.

### 📦 JSON Export

Analysis results can also be exported as structured JSON for further investigation or integration.

---

# 🎨 Professional Cybersecurity Dashboard

MailSentinel Pro includes a redesigned SOC-inspired interface featuring:

* Dark forensic-console aesthetic
* Animated cybersecurity background
* Glassmorphism panels
* Threat-level visualization
* Animated risk gauge
* Security pipeline visualization
* Authentication status chips
* Analysis console
* SIEM-style event log
* Interactive history table
* Drag-and-drop upload area
* Responsive layout
* Reduced-motion accessibility support

The interface is designed to feel closer to a real-world security operations dashboard rather than a basic Flask form.

---

# 🏗️ Project Architecture

```text
mailsentinel-pro/
│
├── app.py
│
├── analyzer/
│   ├── __init__.py
│   ├── auth_checks.py
│   ├── email_parser.py
│   ├── ml_detector.py
│   ├── report.py
│   ├── risk_engine.py
│   ├── threat_intel.py
│   └── url_analyzer.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   ├── script.js
│   └── favicon.svg
│
├── sample_suspicious.eml
├── requirements.txt
├── Procfile
├── render.yaml
├── .gitignore
└── README.md
```

---

# 🔍 Analysis Pipeline

MailSentinel processes an email through several stages.

### 1. Email Parsing

The email parser extracts relevant information from the message:

```text
Headers
Body
Sender
Reply-To
URLs
IP addresses
Attachments
Authentication headers
```

### 2. Identity Analysis

The system checks whether the sender identity appears consistent.

For example:

```text
From:       security@example.com
Reply-To:   attacker@example.net
```

A mismatch can contribute to the overall risk score.

### 3. URL & IOC Analysis

Extracted URLs and IP addresses are analyzed for suspicious characteristics.

### 4. Authentication Analysis

SPF, DKIM and DMARC results are parsed from authentication headers.

```text
SPF     → PASS / FAIL / UNKNOWN
DKIM    → PASS / FAIL / UNKNOWN
DMARC   → PASS / FAIL / UNKNOWN
```

### 5. Phishing Detection

The baseline detector evaluates the subject and body for suspicious language and behavioral indicators.

### 6. Risk Engine

Signals from different modules are combined to calculate an overall risk score.

### 7. Evidence Fingerprinting

The original analyzed content is fingerprinted using SHA-256:

```text
SHA-256(email_content)
```

This provides an evidence identifier that can be used when documenting an investigation.

---

# 🛠️ Technology Stack

| Technology | Purpose                            |
| ---------- | ---------------------------------- |
| Python     | Core application                   |
| Flask      | Web application/API                |
| SQLite     | Analysis history                   |
| HTML5      | Dashboard structure                |
| CSS3       | UI, animations & responsive design |
| JavaScript | Frontend interaction               |
| Gunicorn   | Production WSGI server             |
| SHA-256    | Evidence fingerprinting            |

---

# 📋 Requirements

* Python 3.10+
* pip
* Git
* Modern web browser

---

# ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/mailsentinel-pro.git
cd mailsentinel-pro
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment

#### Windows

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\activate
```

If PowerShell blocks activation, you can run the application directly using:

```powershell
.venv\Scripts\python.exe app.py
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start MailSentinel

```bash
python app.py
```

Or:

```bash
.venv\Scripts\python.exe app.py
```

### 5. Open the dashboard

```text
https://mailsentinel-pro.onrender.com/
```

---

# 🧪 Testing With the Sample Email

A suspicious sample email is included in the repository:

```text
sample_suspicious.eml
```

It demonstrates several suspicious characteristics including:

* Failed SPF
* Failed DKIM
* Failed DMARC
* Reply-To mismatch
* Credential-phishing URL
* Suspicious email indicators

You can also use the dashboard's:

```text
Load Sample .eml
```

option for a quick demonstration.

> ⚠️ The sample is intended for controlled testing and educational demonstration.

---

# 🔌 API Endpoints

MailSentinel exposes several Flask endpoints.

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "ok",
  "service": "Email Threat Intelligence Platform"
}
```

### Analyze Email

```http
POST /analyze
```

Accepts an uploaded email or raw email content.

### Analysis History

```http
GET /api/history
```

Returns previous analyses.

Optional:

```text
/api/history?limit=30
```

### View Analysis

```http
GET /api/history/<id>
```

### Delete Analysis

```http
DELETE /api/history/<id>
```

### Generate Report

```http
POST /report
```

Generates a downloadable HTML forensic report.

---

# 🚀 Deployment

MailSentinel can be deployed using a platform such as Render.

The repository includes:

```text
render.yaml
Procfile
```

Typical deployment configuration:

### Build Command

```bash
pip install -r requirements.txt
```

### Start Command

```bash
gunicorn app:app
```

The application also supports the `PORT` environment variable.

---

# 🔐 Security Considerations

MailSentinel is designed primarily as a cybersecurity learning, demonstration, and analysis platform.

Important considerations:

* Do not upload confidential emails to an untrusted deployment.
* Do not expose sensitive email data publicly.
* Do not commit API keys or credentials.
* Keep `.env` files outside version control.
* Use authenticated external threat-intelligence providers for production deployments.
* Treat automated risk scores as indicators, not definitive proof of malicious activity.
* Run suspicious samples in controlled environments.

The application currently uses a self-contained explainable detection baseline rather than a production-trained machine-learning classifier.

---

# 🧠 Current Detection Model

The included detector is intentionally lightweight and explainable.

It uses heuristic/NLP-style signals rather than claiming to provide definitive machine-learning classification.

For a production-grade deployment, the detection layer could be extended with:

```text
        ┌──────────────────────┐
        │ Licensed Email Dataset│
        └──────────┬───────────┘
                   ▼
        ┌──────────────────────┐
        │ Feature Engineering │
        └──────────┬───────────┘
                   ▼
        ┌──────────────────────┐
        │ ML / Deep Learning   │
        │ Classification Model │
        └──────────┬───────────┘
                   ▼
        ┌──────────────────────┐
        │ Model Evaluation     │
        └──────────┬───────────┘
                   ▼
        ┌──────────────────────┐
        │ MailSentinel Engine  │
        └──────────────────────┘
```

---

# 🔮 Future Roadmap

Potential future improvements include:

* [ ] Trained phishing classification model
* [ ] VirusTotal integration
* [ ] AbuseIPDB integration
* [ ] URL reputation APIs
* [ ] Domain age / WHOIS analysis
* [ ] DNS security checks
* [ ] Advanced attachment sandboxing
* [ ] YARA-based attachment analysis
* [ ] Authentication and user accounts
* [ ] Role-based access control
* [ ] PostgreSQL support
* [ ] Redis/Celery background analysis
* [ ] Real-time threat-intelligence feeds
* [ ] SOC/SIEM integrations
* [ ] PDF forensic reports
* [ ] Investigation case management
* [ ] Analyst notes and tagging
* [ ] Threat analytics dashboard

---

# 🎯 Project Goals

MailSentinel Pro was created to demonstrate how multiple cybersecurity techniques can be combined into a single practical security-analysis workflow.

The project focuses on:

```text
Email Security
      +
Threat Intelligence
      +
Digital Forensics
      +
Risk Analysis
      +
Security Visualization
```

---

# ⚠️ Disclaimer

MailSentinel Pro is an educational and defensive cybersecurity project.

It should not be considered a replacement for professional email-security products, trained security analysts, or verified threat-intelligence services.

Automated results may contain false positives or false negatives.

Only analyze emails and systems that you are authorized to inspect.

---

# 👨‍💻 Author

**Anshul Yadav**

B.Tech Computer Science / Cybersecurity Student
Indore, Madhya Pradesh, India

Interested in:

* Cybersecurity
* Ethical Hacking
* Network Security
* Digital Forensics
* Threat Intelligence
* Security Engineering

---

# ⭐ Support the Project

If you find MailSentinel Pro useful for learning or cybersecurity experimentation:

⭐ Star the repository
🍴 Fork the project
🐛 Report issues
💡 Suggest improvements
🔐 Contribute security enhancements

---

## 📜 License

Add your preferred open-source license before publishing the project publicly.

Recommended for a GitHub portfolio project:

**MIT License**
