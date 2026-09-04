import os
import json
import time

class ScanReporter:
    """Generates comprehensive JSON and HTML forensic reports for scan runs."""
    
    def __init__(self, reports_dir="reports"):
        self.reports_dir = os.path.abspath(reports_dir)
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_reports(self, scan_result):
        """Generates both JSON and HTML report files, returning their paths."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"scan_report_{timestamp}"
        
        json_path = os.path.join(self.reports_dir, f"{base_name}.json")
        html_path = os.path.join(self.reports_dir, f"{base_name}.html")

        # Save JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(scan_result, f, indent=4)

        # Save HTML
        html_content = self._render_html(scan_result)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return json_path, html_path

    def _render_html(self, data):
        threats_html = ""
        threats = data.get("threats", [])
        
        if not threats:
            threats_html = """
            <tr>
                <td colspan="6" style="text-align: center; color: #00ff66; padding: 20px;">
                    🛡️ No malicious threats or suspicious indicators found. Drive is clean.
                </td>
            </tr>
            """
        else:
            for t in threats:
                sev = t.get("severity", "MEDIUM")
                sev_color = "#ff3366" if sev == "CRITICAL" else ("#ff9900" if sev == "HIGH" else "#00e5ff")
                status = "QUARANTINED" if t.get("quarantined") else "DETECTED"
                status_color = "#00ff66" if t.get("quarantined") else "#ff3366"

                threats_html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.85rem;">{t.get('file_path')}</td>
                    <td><strong>{t.get('threat_name')}</strong><br><small style="color: #8892b0;">{t.get('description', '')}</small></td>
                    <td><span style="background: {sev_color}22; color: {sev_color}; padding: 4px 8px; border-radius: 4px; font-weight: bold; border: 1px solid {sev_color};">{sev}</span></td>
                    <td style="font-family: monospace; font-size: 0.8rem; color: #a8b2d1;">{t.get('mitre_attack', 'N/A')}</td>
                    <td style="font-family: monospace; font-size: 0.75rem; color: #8892b0;">{t.get('sha256', 'N/A')[:16]}...</td>
                    <td><span style="color: {status_color}; font-weight: bold;">{status}</span></td>
                </tr>
                """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>USB-Sentinel Forensic Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0a0d14;
            --bg-card: #121824;
            --text-primary: #e6edf3;
            --text-muted: #8b949e;
            --border-color: #30363d;
            --cyber-green: #00ff66;
            --cyber-cyan: #00d4ff;
            --alert-red: #ff3366;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .title {{
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--cyber-cyan);
            margin: 0;
        }}
        .meta-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-val {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: #161f30;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background: #182236;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 0.85rem;
            color: var(--text-muted);
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">🛡️ USB-Sentinel Forensic Scan Report</h1>
                <div style="color: var(--text-muted); margin-top: 5px;">Automated External Drive Incident Response Log</div>
            </div>
            <div style="text-align: right; font-family: monospace; color: var(--cyber-green);">
                STATUS: COMPLETED<br>
                {data.get('timestamp')}
            </div>
        </div>

        <div class="meta-stats">
            <div class="stat-card">
                <div class="stat-label">Target Drive</div>
                <div class="stat-val" style="color: var(--cyber-cyan);">{data.get('target', 'Unknown')}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Files Scanned</div>
                <div class="stat-val">{data.get('files_scanned', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-val" style="color: {'var(--alert-red)' if threats else 'var(--cyber-green)'};">
                    {len(threats)}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Duration</div>
                <div class="stat-val">{data.get('duration_seconds', 0.0)}s</div>
            </div>
        </div>

        <h2 style="font-size: 1.2rem; margin-bottom: 12px;">Detected Threats & Forensic Indicators</h2>
        <table>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>Threat Name / Description</th>
                    <th>Severity</th>
                    <th>MITRE ATT&CK</th>
                    <th>SHA-256 (Prefix)</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {threats_html}
            </tbody>
        </table>

        <div class="footer">
            Generated by <strong>USB-Sentinel</strong> &bull; Author: <strong>DuckWater (@TigerOneTank)</strong> &bull; CyberSecurity-_Projects
        </div>
    </div>
</body>
</html>
        """
        return html
