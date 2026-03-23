"""
Module: open_redirect.py
OWASP  : A01:2021 – Broken Access Control
Purpose: Test URL parameters for open redirect vulnerabilities.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2f@legitimate.com",
    "javascript:alert(1)",
]

REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnUrl",
                   "redirect_uri", "goto", "dest", "destination", "redir", "continue"]


def test_open_redirect(urls, timeout=5):
    """Test redirect-like URL parameters for open redirect."""
    vulns = []
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param in params:
            if param.lower() not in [p.lower() for p in REDIRECT_PARAMS]:
                continue

            for payload in REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(query=urlencode(test_params)).geturl()

                try:
                    resp = requests.get(test_url, headers=HEADERS,
                                        timeout=timeout, verify=False,
                                        allow_redirects=False)
                    location = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and \
                       "evil.com" in location:
                        vulns.append({
                            "url":     test_url,
                            "param":   param,
                            "payload": payload,
                            "detail":  (
                                f"Open redirect in parameter '{param}'. "
                                f"Server redirects to attacker-controlled URL: {location}"
                            )
                        })
                        break
                except Exception:
                    pass
    return vulns
