#!/usr/bin/env python3
"""
================================================
  Web Vulnerability Scanner — OWASP Top 10
  Author  : Ankush Beniwal
  Version : 1.0
  License : MIT (Educational / Authorized Use)
================================================
  ⚠ WARNING: Only scan websites you OWN or have
    WRITTEN PERMISSION to test. Unauthorized
    scanning is ILLEGAL.
================================================
"""

import sys
import time
import argparse
from datetime import datetime
from urllib.parse import urlparse

from modules.crawler        import crawl_site
from modules.sqli           import test_sql_injection
from modules.xss            import test_xss
from modules.headers        import check_security_headers
from modules.dir_traversal  import test_directory_traversal
from modules.open_redirect  import test_open_redirect
from modules.sensitive_files import check_sensitive_files
from modules.csrf           import check_csrf
from modules.cmd_injection  import test_command_injection
from modules.ssl_check      import check_ssl_tls
from modules.broken_auth    import check_broken_auth
from report.generator       import generate_all_reports


# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(t):    return f"{C.RED}{t}{C.RESET}"
def green(t):  return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def cyan(t):   return f"{C.CYAN}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}
{C.YELLOW}        OWASP Top 10 Web Vulnerability Scanner v1.0{C.RESET}
{C.RED}  ⚠  For authorized use only — get written permission first  ⚠{C.RESET}
""")


# ─────────────────────────────────────────────
# SECTION PRINTER
# ─────────────────────────────────────────────

def section(title, owasp_id=""):
    label = f" [{owasp_id}]" if owasp_id else ""
    print(f"\n{bold('─'*55)}")
    print(f"  {cyan('▶')} {bold(title)}{label}")
    print(f"{bold('─'*55)}")


def result_line(label, status, detail=""):
    icon = green("✔ PASS") if status == "pass" else \
           red("✘ VULN") if status == "vuln" else \
           yellow("⚠ WARN")
    suffix = f"  {C.BLUE}{detail}{C.RESET}" if detail else ""
    print(f"  {icon}  {label}{suffix}")


# ─────────────────────────────────────────────
# VALIDATE TARGET
# ─────────────────────────────────────────────

def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        print(red("  ✘ Invalid URL. Example: http://testsite.com"))
        sys.exit(1)
    return url.rstrip("/")


# ─────────────────────────────────────────────
# MAIN SCAN PIPELINE
# ─────────────────────────────────────────────

def run_scan(target, depth=2, timeout=5, output_dir="."):
    start_time = time.time()
    banner()

    target = validate_url(target)
    domain = urlparse(target).netloc

    print(f"  {bold('Target  :')} {cyan(target)}")
    print(f"  {bold('Domain  :')} {domain}")
    print(f"  {bold('Started :')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {bold('Depth   :')} {depth} levels")

    findings = {
        "meta": {
            "target":    target,
            "domain":    domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner":   "WebScan OWASP v1.0",
        },
        "vulnerabilities": []
    }

    def add_finding(owasp_id, name, severity, detail, url=target, fix=""):
        findings["vulnerabilities"].append({
            "owasp_id":  owasp_id,
            "name":      name,
            "severity":  severity,
            "detail":    detail,
            "url":       url,
            "fix":       fix,
        })

    # ── STEP 1: Crawl ─────────────────────────────
    section("CRAWLING SITE", "Recon")
    print(f"  Crawling up to {depth} levels deep...\n")
    urls, forms = crawl_site(target, depth=depth, timeout=timeout)
    print(f"  {green('✔')} Found {len(urls)} URLs  |  {len(forms)} forms")

    # ── STEP 2: SQL Injection ──────────────────────
    section("SQL INJECTION", "A03:2021")
    vulns = test_sql_injection(forms, timeout=timeout)
    if vulns:
        for v in vulns:
            result_line(f"SQLi in form → {v['url']}", "vuln", v['param'])
            add_finding("A03", "SQL Injection", "CRITICAL", v['detail'], v['url'],
                        "Use parameterized queries / prepared statements. Never concatenate user input into SQL.")
    else:
        result_line("No SQL injection found in forms", "pass")

    # ── STEP 3: XSS ───────────────────────────────
    section("CROSS-SITE SCRIPTING (XSS)", "A03:2021")
    xss_vulns = test_xss(forms, urls, timeout=timeout)
    if xss_vulns:
        for v in xss_vulns:
            result_line(f"XSS in {v['type']} → {v['url']}", "vuln", v['param'])
            add_finding("A03", "XSS – " + v['type'], "HIGH", v['detail'], v['url'],
                        "Encode output. Use Content-Security-Policy header. Sanitize all user inputs.")
    else:
        result_line("No XSS vulnerabilities found", "pass")

    # ── STEP 4: Security Headers ───────────────────
    section("MISSING SECURITY HEADERS", "A05:2021")
    header_issues = check_security_headers(target, timeout=timeout)
    if header_issues:
        for h in header_issues:
            result_line(f"Missing: {h['header']}", "warn", h['risk'])
            add_finding("A05", f"Missing Header: {h['header']}", "MEDIUM", h['detail'], target, h['fix'])
    else:
        result_line("All important security headers present", "pass")

    # ── STEP 5: Directory Traversal ────────────────
    section("DIRECTORY TRAVERSAL / PATH TRAVERSAL", "A01:2021")
    trav_vulns = test_directory_traversal(urls, timeout=timeout)
    if trav_vulns:
        for v in trav_vulns:
            result_line(f"Traversal possible → {v['url']}", "vuln")
            add_finding("A01", "Directory Traversal", "HIGH", v['detail'], v['url'],
                        "Validate and sanitize file paths. Use allowlists for file access. Never expose path params directly.")
    else:
        result_line("No directory traversal found", "pass")

    # ── STEP 6: Open Redirect ─────────────────────
    section("OPEN REDIRECT", "A01:2021")
    redirect_vulns = test_open_redirect(urls, timeout=timeout)
    if redirect_vulns:
        for v in redirect_vulns:
            result_line(f"Open redirect → {v['url']}", "vuln")
            add_finding("A01", "Open Redirect", "MEDIUM", v['detail'], v['url'],
                        "Validate redirect destinations against an allowlist. Never redirect to user-supplied URLs.")
    else:
        result_line("No open redirects found", "pass")

    # ── STEP 7: Sensitive Files ───────────────────
    section("SENSITIVE FILE EXPOSURE", "A05:2021")
    exposed = check_sensitive_files(target, timeout=timeout)
    if exposed:
        for f in exposed:
            result_line(f"Exposed: {f['path']}", "vuln", f"Status {f['status']}")
            add_finding("A05", f"Sensitive File: {f['path']}", "HIGH", f['detail'], f['url'],
                        "Block access to sensitive files via web server config. Move them outside web root.")
    else:
        result_line("No sensitive files exposed", "pass")

    # ── STEP 8: CSRF ──────────────────────────────
    section("CSRF – MISSING TOKENS", "A01:2021")
    csrf_issues = check_csrf(forms)
    if csrf_issues:
        for v in csrf_issues:
            result_line(f"Form missing CSRF token → {v['url']}", "vuln")
            add_finding("A01", "Missing CSRF Token", "HIGH", v['detail'], v['url'],
                        "Add CSRF tokens to all state-changing forms. Use SameSite cookie attribute.")
    else:
        result_line("CSRF tokens found in forms", "pass")

    # ── STEP 9: Command Injection ─────────────────
    section("COMMAND INJECTION", "A03:2021")
    cmd_vulns = test_command_injection(forms, timeout=timeout)
    if cmd_vulns:
        for v in cmd_vulns:
            result_line(f"Possible cmd injection → {v['url']}", "vuln", v['param'])
            add_finding("A03", "Command Injection", "CRITICAL", v['detail'], v['url'],
                        "Never pass user input to system commands. Use safe APIs. Validate/sanitize all input.")
    else:
        result_line("No command injection found", "pass")

    # ── STEP 10: SSL/TLS ──────────────────────────
    section("SSL/TLS MISCONFIGURATION", "A02:2021")
    ssl_issues = check_ssl_tls(target, timeout=timeout)
    if ssl_issues:
        for s in ssl_issues:
            result_line(f"{s['issue']}", "warn", s['detail'])
            add_finding("A02", f"SSL/TLS: {s['issue']}", s['severity'], s['detail'], target, s['fix'])
    else:
        result_line("SSL/TLS configuration looks good", "pass")

    # ── STEP 11: Broken Auth ──────────────────────
    section("BROKEN AUTHENTICATION", "A07:2021")
    auth_issues = check_broken_auth(target, forms, timeout=timeout)
    if auth_issues:
        for a in auth_issues:
            result_line(f"{a['issue']}", "warn", a['detail'])
            add_finding("A07", f"Auth: {a['issue']}", a['severity'], a['detail'], target, a['fix'])
    else:
        result_line("No obvious authentication issues found", "pass")

    # ── SUMMARY ───────────────────────────────────
    elapsed = round(time.time() - start_time, 2)
    vulns_found = findings["vulnerabilities"]
    critical = [v for v in vulns_found if v["severity"] == "CRITICAL"]
    high     = [v for v in vulns_found if v["severity"] == "HIGH"]
    medium   = [v for v in vulns_found if v["severity"] == "MEDIUM"]

    print(f"\n{bold('═'*55)}")
    print(f"  {bold('SCAN COMPLETE')}  ({elapsed}s)")
    print(f"  URLs Scanned     : {green(str(len(urls)))}")
    print(f"  Forms Tested     : {green(str(len(forms)))}")
    print(f"  Total Findings   : {bold(str(len(vulns_found)))}")
    print(f"  Critical         : {red(str(len(critical)))}")
    print(f"  High             : {yellow(str(len(high)))}")
    print(f"  Medium           : {yellow(str(len(medium)))}")
    print(f"{bold('═'*55)}")

    findings["meta"]["total_findings"] = len(vulns_found)
    findings["meta"]["critical"] = len(critical)
    findings["meta"]["high"] = len(high)
    findings["meta"]["medium"] = len(medium)
    findings["meta"]["scan_duration"] = elapsed

    # ── REPORTS ───────────────────────────────────
    section("GENERATING REPORTS")
    generate_all_reports(findings, output_dir=output_dir)

    return findings


# ─────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — OWASP Top 10",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python3 scanner.py http://testsite.com\n  python3 scanner.py http://testsite.com --depth 3 --output ./reports"
    )
    parser.add_argument("target",              help="Target URL (e.g. http://192.168.1.1)")
    parser.add_argument("--depth",   type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout seconds (default: 5)")
    parser.add_argument("--output",            default=".",   help="Output directory for reports")

    args = parser.parse_args()
    run_scan(args.target, depth=args.depth, timeout=args.timeout, output_dir=args.output)
