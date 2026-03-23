"""
Module: csrf.py
OWASP  : A01:2021 – Broken Access Control
Purpose: Detect forms that are missing CSRF protection tokens.
"""

CSRF_TOKEN_NAMES = [
    "csrf",
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",   # Django
    "__requestverificationtoken",  # ASP.NET
    "authenticity_token",    # Rails
    "_csrf",
    "xsrf-token",
    "x-csrf-token",
]


def check_csrf(forms):
    """
    Check each POST form for the presence of CSRF tokens.
    A form is vulnerable if it:
    1. Uses POST method (state-changing)
    2. Has no hidden input that looks like a CSRF token
    """
    issues = []
    for form in forms:
        # Only POST forms matter for CSRF
        if form["method"] != "post":
            continue

        # Check if any input looks like a CSRF token
        has_token = False
        for inp in form["inputs"]:
            name_lower = inp["name"].lower()
            if any(token in name_lower for token in CSRF_TOKEN_NAMES):
                has_token = True
                break

        if not has_token:
            # Ignore forms that only have file upload or non-sensitive fields
            non_trivial = any(
                inp["type"] not in ("submit", "button", "image", "reset")
                for inp in form["inputs"]
            )
            if non_trivial:
                issues.append({
                    "url":    form["action"],
                    "method": form["method"],
                    "fields": [i["name"] for i in form["inputs"]],
                    "detail": (
                        f"POST form at {form['action']} has no CSRF token. "
                        f"Attacker can forge requests on behalf of logged-in users."
                    )
                })
    return issues
