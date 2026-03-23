"""
Module: broken_auth.py
OWASP  : A07:2021 – Identification & Authentication Failures
Purpose: Check for common authentication weaknesses.
"""

import requests

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

# Default credentials to try on login forms
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("root",  "root"),
    ("root",  "toor"),
    ("test",  "test"),
]

# Login success/failure indicators
FAIL_KEYWORDS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "denied", "unauthorized", "bad credentials", "try again"
]


def find_login_forms(forms):
    """Find forms that look like login forms."""
    login_forms = []
    for form in forms:
        has_password = any(i["type"] == "password" for i in form["inputs"])
        has_username = any(
            i["type"] in ("text", "email") or
            any(k in i["name"].lower() for k in ["user", "email", "login", "name"])
            for i in form["inputs"]
        )
        if has_password and has_username:
            login_forms.append(form)
    return login_forms


def submit_form(form, data, timeout=5):
    """Submit a form with given data."""
    try:
        if form["method"] == "post":
            return requests.post(form["action"], data=data,
                                 headers=HEADERS, timeout=timeout, verify=False,
                                 allow_redirects=True)
        else:
            return requests.get(form["action"], params=data,
                                headers=HEADERS, timeout=timeout, verify=False)
    except Exception:
        return None


def check_broken_auth(target_url, forms, timeout=5):
    """Run authentication checks on the target."""
    issues = []

    login_forms = find_login_forms(forms)

    # ── Check 1: Default credentials ──
    for form in login_forms:
        user_field = next(
            (i["name"] for i in form["inputs"]
             if i["type"] in ("text", "email") or
             any(k in i["name"].lower() for k in ["user", "email", "login"])),
            None
        )
        pass_field = next(
            (i["name"] for i in form["inputs"] if i["type"] == "password"), None
        )
        if not user_field or not pass_field:
            continue

        for username, password in DEFAULT_CREDS:
            data = {i["name"]: i["value"] or "" for i in form["inputs"]}
            data[user_field] = username
            data[pass_field] = password

            resp = submit_form(form, data, timeout)
            if resp:
                text_lower = resp.text.lower()
                # If response doesn't contain failure keywords, assume login succeeded
                if not any(kw in text_lower for kw in FAIL_KEYWORDS):
                    issues.append({
                        "issue":    f"Default credentials work: {username}/{password}",
                        "severity": "CRITICAL",
                        "detail":   f"Login form at {form['action']} accepted default creds: {username}/{password}",
                        "fix":      "Change default credentials immediately. Enforce strong password policy."
                    })
                    break

    # ── Check 2: Login page without HTTPS ──
    if login_forms and not target_url.startswith("https://"):
        issues.append({
            "issue":    "Login form on HTTP (unencrypted)",
            "severity": "CRITICAL",
            "detail":   "Login form found on plain HTTP — passwords transmitted in clear text.",
            "fix":      "Move all authentication pages to HTTPS only."
        })

    # ── Check 3: Account enumeration via response difference ──
    for form in login_forms:
        user_field = next(
            (i["name"] for i in form["inputs"]
             if i["type"] in ("text", "email")), None
        )
        pass_field = next(
            (i["name"] for i in form["inputs"] if i["type"] == "password"), None
        )
        if not user_field or not pass_field:
            continue

        data_valid   = {i["name"]: i["value"] or "" for i in form["inputs"]}
        data_invalid = {i["name"]: i["value"] or "" for i in form["inputs"]}

        data_valid[user_field]   = "admin"
        data_invalid[user_field] = "zzz_nonexistent_user_xyz"
        data_valid[pass_field]   = "wrongpass"
        data_invalid[pass_field] = "wrongpass"

        resp1 = submit_form(form, data_valid, timeout)
        resp2 = submit_form(form, data_invalid, timeout)

        if resp1 and resp2:
            # If responses differ significantly, username enumeration is possible
            len_diff = abs(len(resp1.text) - len(resp2.text))
            if len_diff > 50:
                issues.append({
                    "issue":    "Username enumeration possible",
                    "severity": "MEDIUM",
                    "detail":   (
                        f"Login form returns different responses for valid vs invalid usernames "
                        f"(response length difference: {len_diff} chars)."
                    ),
                    "fix":      "Return identical error messages for both invalid username and invalid password."
                })

    # ── Check 4: No account lockout ──
    for form in login_forms:
        user_field = next(
            (i["name"] for i in form["inputs"]
             if i["type"] in ("text", "email")), None
        )
        pass_field = next(
            (i["name"] for i in form["inputs"] if i["type"] == "password"), None
        )
        if not user_field or not pass_field:
            continue

        # Try 5 consecutive bad logins
        blocked = False
        for _ in range(5):
            data = {i["name"]: i["value"] or "" for i in form["inputs"]}
            data[user_field] = "admin"
            data[pass_field] = "bad_password_attempt"
            resp = submit_form(form, data, timeout)
            if resp and ("locked" in resp.text.lower() or
                         "too many" in resp.text.lower() or
                         resp.status_code == 429):
                blocked = True
                break

        if not blocked:
            issues.append({
                "issue":    "No account lockout / rate limiting",
                "severity": "MEDIUM",
                "detail":   "Login form allows unlimited attempts — vulnerable to brute force attacks.",
                "fix":      "Implement account lockout after 5 failed attempts. Add CAPTCHA. Use rate limiting."
            })
        break  # Only test first login form to avoid excessive requests

    return issues
