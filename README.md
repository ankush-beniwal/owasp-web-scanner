# 🔐 Web Vulnerability Scanner — OWASP Top 10

> ⚠️ **DISCLAIMER**: Only scan websites you **own** or have **written permission** to test.
> Unauthorized scanning is **illegal** under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---

## 📌 What This Does

A Python-based web vulnerability scanner that automatically tests a target website for **OWASP Top 10** vulnerabilities — the industry standard checklist used by professional penetration testers.

---

## ✅ Vulnerabilities Covered

| # | OWASP ID | Vulnerability | Module |
|---|----------|--------------|--------|
| 1 | A03:2021 | **SQL Injection** (error + time-based blind) | `sqli.py` |
| 2 | A03:2021 | **Cross-Site Scripting (XSS)** (reflected, URL params) | `xss.py` |
| 3 | A05:2021 | **Missing Security Headers** (CSP, HSTS, X-Frame-Options...) | `headers.py` |
| 4 | A01:2021 | **Directory / Path Traversal** | `dir_traversal.py` |
| 5 | A01:2021 | **Open Redirect** | `open_redirect.py` |
| 6 | A05:2021 | **Sensitive File Exposure** (.env, .git, phpinfo, backups...) | `sensitive_files.py` |
| 7 | A01:2021 | **Missing CSRF Tokens** | `csrf.py` |
| 8 | A03:2021 | **Command Injection** (response + time-based) | `cmd_injection.py` |
| 9 | A02:2021 | **SSL/TLS Misconfiguration** (no HTTPS, old TLS, no HSTS) | `ssl_check.py` |
| 10| A07:2021 | **Broken Authentication** (default creds, no lockout, enumeration) | `broken_auth.py` |

---

## 🗂️ Project Structure

```
web_vuln_scanner/
│
├── scanner.py              ← Main entry point (run this)
├── requirements.txt        ← pip dependencies
├── README.md               ← This file
│
├── modules/
│   ├── __init__.py
│   ├── crawler.py          ← BFS web crawler (finds URLs & forms)
│   ├── sqli.py             ← SQL injection tester
│   ├── xss.py              ← XSS tester
│   ├── headers.py          ← Security headers checker
│   ├── dir_traversal.py    ← Path traversal tester
│   ├── open_redirect.py    ← Open redirect tester
│   ├── sensitive_files.py  ← Exposed file checker
│   ├── csrf.py             ← CSRF token checker
│   ├── cmd_injection.py    ← Command injection tester
│   ├── ssl_check.py        ← SSL/TLS analyzer
│   └── broken_auth.py      ← Auth weakness checker
│
└── report/
    ├── __init__.py
    └── generator.py        ← Generates HTML / JSON / TXT reports
```

---

## 🚀 Quick Start

### Step 1 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Run a scan

**Full scan (recommended):**
```bash
python3 scanner.py http://target-site.com
```

**With options:**
```bash
python3 scanner.py http://target-site.com --depth 3 --timeout 8 --output ./reports
```

### Step 3 — View your report
The scanner generates 3 report files automatically:
- `report_*.html` — Open in browser for a beautiful dashboard
- `report_*.json` — Machine-readable structured data
- `report_*.txt`  — Plain text summary

---

## ⚙️ Options

| Option | Default | Description |
|--------|---------|-------------|
| `target` | (required) | Target URL — e.g., `http://192.168.1.1` |
| `--depth` | 2 | How many levels deep to crawl the site |
| `--timeout` | 5 | Request timeout in seconds |
| `--output` | `.` | Directory to save reports |

---

## 🧪 Safe Practice Targets

**Never scan real sites. Use these instead:**

| Target | What It Is | Link |
|--------|-----------|------|
| **DVWA** | Damn Vulnerable Web App | [github.com/digininja/DVWA](https://github.com/digininja/DVWA) |
| **Juice Shop** | OWASP's vulnerable Node.js app | [github.com/juice-shop](https://github.com/juice-shop/juice-shop) |
| **WebGoat** | OWASP learning platform | [github.com/WebGoat](https://github.com/WebGoat/WebGoat) |
| **HackTheBox** | Online lab machines | [hackthebox.com](https://hackthebox.com) |
| **TryHackMe** | Guided web hacking rooms | [tryhackme.com](https://tryhackme.com) |

**Run DVWA locally:**
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
python3 scanner.py http://localhost
```

---

## 📊 Example Output

```
──────────────────────────────────────────────────────
  ▶ SQL INJECTION [A03:2021]
──────────────────────────────────────────────────────
  ✘ VULN  SQLi in form → http://site.com/login  username

──────────────────────────────────────────────────────
  ▶ MISSING SECURITY HEADERS [A05:2021]
──────────────────────────────────────────────────────
  ⚠ WARN  Missing: Content-Security-Policy    HIGH
  ⚠ WARN  Missing: Strict-Transport-Security  HIGH
  ✔ PASS  X-Content-Type-Options present

═══════════════════════════════════════════════════════
  SCAN COMPLETE  (18.4s)
  URLs Scanned     : 23
  Forms Tested     : 6
  Total Findings   : 8
  Critical         : 2
  High             : 4
  Medium           : 2
═══════════════════════════════════════════════════════
```

---

## 🔮 Future Improvements

- [ ] Add IDOR (Insecure Direct Object Reference) testing
- [ ] Add XXE (XML External Entity) testing
- [ ] Add subdomain enumeration
- [ ] Add JavaScript file analysis for hardcoded secrets
- [ ] Add CVSS score per finding
- [ ] Export PDF report
- [ ] Add Slack/email alerting

---

## 🛠️ How It Works (For Beginners)

### 1. Crawling
```python
# We visit every page and find all URLs and HTML forms
urls, forms = crawl_site("http://target.com", depth=2)
```

### 2. SQL Injection
```python
# We inject SQL payloads into every form field
data["username"] = "' OR '1'='1"
# If the response has SQL error text → vulnerable!
```

### 3. XSS Detection
```python
# We inject script tags and check if they appear in the response
data["search"] = "<script>alert('XSS')</script>"
if payload in response.text:
    # Site reflects the script → XSS found!
```

### 4. Report Generation
```python
# All findings are collected into a JSON structure
# Then exported to HTML, JSON, and TXT formats
generate_all_reports(findings, output_dir="./reports")
```

---

## 👤 Author

Ankush Beniwal
🔐 Penetration Testing | Python Security Tools
📍 India

---

*Built with 🐍 Python for the cybersecurity community. Educational use only.*
