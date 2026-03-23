"""
Module: sensitive_files.py
OWASP  : A05:2021 – Security Misconfiguration
Purpose: Check if sensitive files/paths are publicly accessible.
"""

import requests

HEADERS = {"User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"}

SENSITIVE_PATHS = [
    ("/.env",                "Environment variables — DB passwords, API keys"),
    ("/.git/config",         "Git repository config — source code exposure"),
    ("/.git/HEAD",           "Git HEAD file"),
    ("/config.php",          "PHP config file — DB credentials"),
    ("/wp-config.php",       "WordPress config — DB credentials"),
    ("/phpinfo.php",         "PHP info page — server internals exposed"),
    ("/admin",               "Admin panel exposed"),
    ("/admin/login",         "Admin login page exposed"),
    ("/debug",               "Debug endpoint exposed"),
    ("/api/v1/users",        "User API endpoint exposed"),
    ("/backup.zip",          "Backup archive exposed"),
    ("/backup.tar.gz",       "Backup archive exposed"),
    ("/database.sql",        "SQL dump exposed"),
    ("/db.sqlite",           "SQLite database exposed"),
    ("/web.config",          "IIS web.config — sensitive config"),
    ("/.htaccess",           "Apache config exposed"),
    ("/robots.txt",          "robots.txt — may reveal hidden paths"),
    ("/sitemap.xml",         "Sitemap — lists all URLs"),
    ("/.DS_Store",           "macOS directory structure exposed"),
    ("/server-status",       "Apache server status page"),
    ("/actuator",            "Spring Boot actuator — system info"),
    ("/actuator/health",     "Spring Boot health endpoint"),
    ("/swagger-ui.html",     "Swagger API docs exposed"),
    ("/api-docs",            "API documentation exposed"),
    ("/.well-known/security.txt", "Security contact file (informational)"),
]


def check_sensitive_files(base_url, timeout=5):
    """Check if any sensitive paths are accessible on the target."""
    exposed = []
    for path, description in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False,
                                allow_redirects=False)
            # 200 = exposed, 403 = exists but blocked (still noteworthy)
            if resp.status_code == 200:
                exposed.append({
                    "path":   path,
                    "url":    url,
                    "status": resp.status_code,
                    "detail": f"{description}. File is publicly accessible (HTTP 200)."
                })
            elif resp.status_code == 403:
                exposed.append({
                    "path":   path,
                    "url":    url,
                    "status": resp.status_code,
                    "detail": f"{description}. File exists but access is forbidden (HTTP 403) — still a risk."
                })
        except Exception:
            pass
    return exposed
