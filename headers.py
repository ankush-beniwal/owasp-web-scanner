"""
Module: headers.py
OWASP  : A05:2021 – Security Misconfiguration
Purpose: Check HTTP response headers for missing or weak security headers.
"""

import requests

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

# ── Headers to check ────────────────────────────────────────────────────
# Each entry: header name, risk level, description, recommended value, fix

SECURITY_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "risk":   "HIGH",
        "detail": "Missing CSP allows attackers to inject and execute malicious scripts (XSS).",
        "fix":    "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    {
        "header": "X-Frame-Options",
        "risk":   "MEDIUM",
        "detail": "Without this header, the site can be embedded in iframes — enabling clickjacking attacks.",
        "fix":    "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"
    },
    {
        "header": "X-Content-Type-Options",
        "risk":   "MEDIUM",
        "detail": "Missing header allows browsers to MIME-sniff responses, enabling content injection.",
        "fix":    "Add: X-Content-Type-Options: nosniff"
    },
    {
        "header": "Strict-Transport-Security",
        "risk":   "HIGH",
        "detail": "Missing HSTS allows downgrade attacks — users can be redirected to insecure HTTP.",
        "fix":    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
        "header": "Referrer-Policy",
        "risk":   "LOW",
        "detail": "Without Referrer-Policy, sensitive URL data may leak to third-party sites.",
        "fix":    "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "header": "Permissions-Policy",
        "risk":   "LOW",
        "detail": "Missing Permissions-Policy allows unrestricted access to browser APIs (camera, mic, geolocation).",
        "fix":    "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    },
    {
        "header": "X-XSS-Protection",
        "risk":   "LOW",
        "detail": "Legacy header — but its absence on older browsers allows reflected XSS.",
        "fix":    "Add: X-XSS-Protection: 1; mode=block"
    },
    {
        "header": "Cache-Control",
        "risk":   "LOW",
        "detail": "Without Cache-Control, sensitive pages may be cached by browsers or proxies.",
        "fix":    "Add: Cache-Control: no-store, no-cache for sensitive pages"
    },
]

# ── Headers that reveal too much info ───────────────────────────────────
INFO_LEAK_HEADERS = [
    "Server",        # Reveals web server software + version
    "X-Powered-By",  # Reveals backend language (PHP, ASP.NET etc)
    "X-AspNet-Version",
    "X-Generator",
]


def check_security_headers(target_url, timeout=5):
    """
    Fetch target and check for missing/weak security headers.
    Returns list of issue dicts.
    """
    issues = []
    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=timeout, verify=False)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # ── Check for missing security headers ──
        for h in SECURITY_HEADERS:
            if h["header"].lower() not in resp_headers:
                issues.append({
                    "header": h["header"],
                    "risk":   h["risk"],
                    "detail": h["detail"],
                    "fix":    h["fix"],
                    "type":   "missing"
                })

        # ── Check for information-leaking headers ──
        for h in INFO_LEAK_HEADERS:
            if h.lower() in resp_headers:
                val = resp_headers[h.lower()]
                issues.append({
                    "header": f"{h} (info leak)",
                    "risk":   "LOW",
                    "detail": f"Server reveals: {h}: {val} — attackers use this to target known vulnerabilities.",
                    "fix":    f"Remove or obfuscate the '{h}' header in your web server configuration.",
                    "type":   "info_leak"
                })

    except Exception as e:
        issues.append({
            "header": "Connection Error",
            "risk":   "INFO",
            "detail": str(e),
            "fix":    "",
            "type":   "error"
        })

    return issues
