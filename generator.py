"""
Module: generator.py
Purpose: Generate JSON, TXT, and HTML reports from scan findings.
"""

import json
import os
from datetime import datetime


# ─────────────────────────────────────────────────────────────────
# SEVERITY COLORS & ICONS
# ─────────────────────────────────────────────────────────────────

SEVERITY_CONFIG = {
    "CRITICAL": {"color": "#e53e3e", "bg": "#fff5f5", "icon": "🔴"},
    "HIGH":     {"color": "#dd6b20", "bg": "#fffaf0", "icon": "🟠"},
    "MEDIUM":   {"color": "#d69e2e", "bg": "#fffff0", "icon": "🟡"},
    "LOW":      {"color": "#38a169", "bg": "#f0fff4", "icon": "🟢"},
    "INFO":     {"color": "#3182ce", "bg": "#ebf8ff", "icon": "🔵"},
}


def get_severity_config(severity):
    return SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["INFO"])


# ─────────────────────────────────────────────────────────────────
# TXT REPORT
# ─────────────────────────────────────────────────────────────────

def generate_txt_report(findings, output_dir="."):
    meta   = findings["meta"]
    vulns  = findings["vulnerabilities"]
    ts     = meta["scan_time"].replace(":", "-").replace(" ", "_")
    domain = meta["domain"].replace(".", "_")
    path   = os.path.join(output_dir, f"report_{domain}_{ts}.txt")

    with open(path, "w") as f:
        f.write("=" * 65 + "\n")
        f.write("     WEB VULNERABILITY SCANNER — PENTEST REPORT\n")
        f.write("=" * 65 + "\n")
        f.write(f"  Target      : {meta['target']}\n")
        f.write(f"  Scan Date   : {meta['scan_time']}\n")
        f.write(f"  Duration    : {meta.get('scan_duration', '?')}s\n")
        f.write(f"  Scanner     : {meta['scanner']}\n")
        f.write(f"  Total Finds : {meta.get('total_findings', 0)}\n")
        f.write(f"  Critical    : {meta.get('critical', 0)}\n")
        f.write(f"  High        : {meta.get('high', 0)}\n")
        f.write(f"  Medium      : {meta.get('medium', 0)}\n")
        f.write("=" * 65 + "\n\n")
        f.write("DISCLAIMER: For authorized penetration testing only.\n\n")

        if not vulns:
            f.write("No vulnerabilities found.\n")
        else:
            for i, v in enumerate(vulns, 1):
                f.write(f"\n[{i}] {v['owasp_id']} — {v['name']}\n")
                f.write(f"     Severity : {v['severity']}\n")
                f.write(f"     URL      : {v['url']}\n")
                f.write(f"     Detail   : {v['detail']}\n")
                f.write(f"     Fix      : {v['fix']}\n")
                f.write("-" * 65 + "\n")

    return path


# ─────────────────────────────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────────────────────────────

def generate_json_report(findings, output_dir="."):
    meta   = findings["meta"]
    ts     = meta["scan_time"].replace(":", "-").replace(" ", "_")
    domain = meta["domain"].replace(".", "_")
    path   = os.path.join(output_dir, f"report_{domain}_{ts}.json")

    with open(path, "w") as f:
        json.dump(findings, f, indent=2)

    return path


# ─────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────

def generate_html_report(findings, output_dir="."):
    meta   = findings["meta"]
    vulns  = findings["vulnerabilities"]
    ts     = meta["scan_time"].replace(":", "-").replace(" ", "_")
    domain = meta["domain"].replace(".", "_")
    path   = os.path.join(output_dir, f"report_{domain}_{ts}.html")

    critical = meta.get("critical", 0)
    high     = meta.get("high", 0)
    medium   = meta.get("medium", 0)
    total    = meta.get("total_findings", 0)

    # Build findings HTML
    findings_html = ""
    if not vulns:
        findings_html = "<div class='no-vulns'>✔ No vulnerabilities detected.</div>"
    else:
        for i, v in enumerate(vulns, 1):
            sc = get_severity_config(v["severity"])
            findings_html += f"""
        <div class="finding" style="border-left:4px solid {sc['color']};background:{sc['bg']}">
          <div class="finding-header">
            <span class="finding-num">#{i}</span>
            <span class="finding-name">{v['name']}</span>
            <span class="finding-owasp">{v['owasp_id']}</span>
            <span class="badge" style="background:{sc['color']}">{sc['icon']} {v['severity']}</span>
          </div>
          <div class="finding-body">
            <div class="detail-row"><span class="label">URL</span><code>{v['url']}</code></div>
            <div class="detail-row"><span class="label">Detail</span><span>{v['detail']}</span></div>
            <div class="detail-row fix-row"><span class="label">Fix</span><span>{v['fix']}</span></div>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — {meta['domain']}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);padding:40px;border-bottom:1px solid #334155}}
  .header-top{{display:flex;align-items:center;gap:16px;margin-bottom:20px}}
  .logo{{font-size:32px}}
  .title{{font-size:26px;font-weight:700;color:#f1f5f9}}
  .subtitle{{font-size:14px;color:#64748b;margin-top:2px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:20px}}
  .meta-card{{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px}}
  .meta-label{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#64748b;margin-bottom:4px}}
  .meta-value{{font-size:15px;font-weight:600;color:#f1f5f9}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:24px 40px;background:#0f172a}}
  .stat{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;border:1px solid #334155}}
  .stat-num{{font-size:32px;font-weight:700;margin-bottom:4px}}
  .stat-label{{font-size:12px;color:#64748b;text-transform:uppercase}}
  .stat.critical .stat-num{{color:#ef4444}}
  .stat.high     .stat-num{{color:#f97316}}
  .stat.medium   .stat-num{{color:#eab308}}
  .stat.total    .stat-num{{color:#60a5fa}}
  .section{{padding:24px 40px}}
  .section-title{{font-size:18px;font-weight:600;color:#f1f5f9;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #334155}}
  .finding{{border-radius:10px;margin-bottom:16px;overflow:hidden}}
  .finding-header{{display:flex;align-items:center;gap:10px;padding:14px 16px;flex-wrap:wrap}}
  .finding-num{{font-size:12px;color:#64748b;background:#1e293b;border-radius:4px;padding:2px 8px}}
  .finding-name{{font-weight:600;color:#1e293b;flex:1;font-size:15px}}
  .finding-owasp{{font-size:11px;color:#475569;background:rgba(0,0,0,.1);border-radius:4px;padding:2px 8px}}
  .badge{{font-size:11px;color:#fff;border-radius:20px;padding:3px 10px;font-weight:600}}
  .finding-body{{padding:12px 16px;background:rgba(255,255,255,.5);border-top:1px solid rgba(0,0,0,.08)}}
  .detail-row{{display:flex;gap:12px;margin-bottom:8px;font-size:13px;color:#1e293b}}
  .label{{font-weight:600;min-width:60px;color:#475569}}
  code{{font-family:monospace;background:rgba(0,0,0,.1);border-radius:4px;padding:1px 6px;word-break:break-all;font-size:12px}}
  .fix-row{{background:rgba(16,185,129,.08);border-radius:6px;padding:8px;border:1px solid rgba(16,185,129,.2)}}
  .no-vulns{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:32px;text-align:center;color:#10b981;font-size:18px}}
  .footer{{text-align:center;padding:24px;color:#475569;font-size:12px;border-top:1px solid #334155}}
  @media(max-width:600px){{.stats{{grid-template-columns:1fr 1fr}}.section{{padding:16px}}}}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">🔐</div>
    <div>
      <div class="title">Web Vulnerability Scan Report</div>
      <div class="subtitle">OWASP Top 10 Assessment — {meta['scanner']}</div>
    </div>
  </div>
  <div class="meta-grid">
    <div class="meta-card"><div class="meta-label">Target</div><div class="meta-value">{meta['domain']}</div></div>
    <div class="meta-card"><div class="meta-label">Full URL</div><div class="meta-value" style="font-size:12px;word-break:break-all">{meta['target']}</div></div>
    <div class="meta-card"><div class="meta-label">Scan Date</div><div class="meta-value">{meta['scan_time']}</div></div>
    <div class="meta-card"><div class="meta-label">Duration</div><div class="meta-value">{meta.get('scan_duration','?')}s</div></div>
  </div>
</div>

<div class="stats">
  <div class="stat total"><div class="stat-num">{total}</div><div class="stat-label">Total Findings</div></div>
  <div class="stat critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
</div>

<div class="section">
  <div class="section-title">Vulnerability Findings</div>
  {findings_html}
</div>

<div class="footer">
  ⚠ This report was generated for authorized penetration testing only.<br>
  Generated by {meta['scanner']} on {meta['scan_time']}
</div>

</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    return path


# ─────────────────────────────────────────────────────────────────
# GENERATE ALL REPORTS
# ─────────────────────────────────────────────────────────────────

def generate_all_reports(findings, output_dir="."):
    os.makedirs(output_dir, exist_ok=True)

    json_path = generate_json_report(findings, output_dir)
    txt_path  = generate_txt_report(findings, output_dir)
    html_path = generate_html_report(findings, output_dir)

    green = "\033[92m"
    reset = "\033[0m"
    print(f"  {green}✔{reset} HTML Report  → {html_path}")
    print(f"  {green}✔{reset} JSON Report  → {json_path}")
    print(f"  {green}✔{reset} TXT Report   → {txt_path}")
    print(f"\n  Open the HTML report in your browser for the best view!")

    return html_path, json_path, txt_path
