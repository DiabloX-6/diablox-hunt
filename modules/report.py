import json
import os
from datetime import datetime


def save_json_report(result, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/scan_{result['domain']}_{int(datetime.now().timestamp())}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=2, default=str)
    return filename


def save_html_report(result, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/report_{result['domain']}_{int(datetime.now().timestamp())}.html"

    findings = result.get("findings", [])
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

    sev_count = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Scan Report - {result['domain']}</title>
<style>
body {{ font-family: Arial, sans-serif; background: #0a0e1a; color: #eee; padding: 20px; }}
h1 {{ color: #00ff88; }}
.header {{ background: #111827; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
.sev {{ display: inline-block; padding: 4px 10px; border-radius: 4px; margin: 2px; font-weight: bold; }}
.CRITICAL {{ background: #ff0000; }}
.HIGH {{ background: #ff6600; }}
.MEDIUM {{ background: #ffcc00; color: #000; }}
.LOW {{ background: #66ccff; color: #000; }}
.INFO {{ background: #888; }}
.finding {{ background: #111827; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #00ff88; }}
.url {{ color: #66ccff; word-break: break-all; font-family: monospace; }}
.evidence {{ color: #aaa; font-family: monospace; font-size: 12px; margin-top: 5px; }}
</style></head><body>
<h1>🔍 Scan Report: {result['domain']}</h1>
<div class="header">
<p><b>Target:</b> {result['target']}</p>
<p><b>IP:</b> {result['ip']}</p>
<p><b>Waktu:</b> {result['time']}</p>
<p><b>Total Findings:</b> {len(findings)}</p>
<p>"""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_count:
            html += f'<span class="sev {sev}">{sev}: {sev_count[sev]}</span> '
    html += "</p></div>"

    for f in findings:
        html += f"""
<div class="finding">
<h3><span class="sev {f['severity']}">{f['severity']}</span> {f['name']}</h3>
<p class="url">{f['url']}</p>
<p class="evidence">{f.get('evidence', '')}</p>
</div>"""

    html += "</body></html>"

    with open(filename, "w") as f:
        f.write(html)
    return filename
