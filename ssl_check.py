"""
Module: ssl_check.py
OWASP  : A02:2021 – Cryptographic Failures
Purpose: Check SSL/TLS configuration for weaknesses.
"""

import socket
import ssl
import requests
from urllib.parse import urlparse

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}


def check_ssl_tls(target_url, timeout=5):
    """Check SSL/TLS configuration of the target."""
    issues = []
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # ── Check 1: Is HTTPS used at all? ──
    if parsed.scheme != "https":
        issues.append({
            "issue":    "Site not using HTTPS",
            "severity": "CRITICAL",
            "detail":   "All traffic is transmitted in plain text. Passwords and data can be intercepted.",
            "fix":      "Install an SSL/TLS certificate. Use Let's Encrypt (free). Redirect all HTTP to HTTPS."
        })
        return issues  # Can't check SSL if not HTTPS

    # ── Check 2: Certificate validity ──
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()

                # Check protocol version
                if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    issues.append({
                        "issue":    f"Outdated TLS version: {proto}",
                        "severity": "HIGH",
                        "detail":   f"Server supports {proto} which is deprecated and vulnerable to attacks.",
                        "fix":      "Configure server to use TLSv1.2 minimum. Prefer TLSv1.3."
                    })

    except ssl.SSLCertVerificationError as e:
        issues.append({
            "issue":    "SSL Certificate invalid or self-signed",
            "severity": "HIGH",
            "detail":   f"Certificate error: {str(e)[:100]}",
            "fix":      "Install a valid certificate from a trusted CA (e.g., Let's Encrypt)."
        })
    except ssl.SSLError as e:
        issues.append({
            "issue":    "SSL Error",
            "severity": "MEDIUM",
            "detail":   str(e)[:100],
            "fix":      "Check your SSL/TLS configuration."
        })
    except Exception:
        pass

    # ── Check 3: HTTP to HTTPS redirect ──
    try:
        http_url = target_url.replace("https://", "http://", 1)
        resp = requests.get(http_url, headers=HEADERS, timeout=timeout,
                            verify=False, allow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            issues.append({
                "issue":    "No HTTP → HTTPS redirect",
                "severity": "MEDIUM",
                "detail":   "Server does not redirect HTTP traffic to HTTPS. Users may accidentally use insecure HTTP.",
                "fix":      "Add a 301 redirect from HTTP to HTTPS in your web server config."
            })
    except Exception:
        pass

    # ── Check 4: HSTS present ──
    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=timeout, verify=False)
        if "strict-transport-security" not in {k.lower() for k in resp.headers}:
            issues.append({
                "issue":    "HSTS header missing",
                "severity": "MEDIUM",
                "detail":   "Without HSTS, browsers won't enforce HTTPS on future visits. Downgrade attacks possible.",
                "fix":      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            })
    except Exception:
        pass

    return issues
