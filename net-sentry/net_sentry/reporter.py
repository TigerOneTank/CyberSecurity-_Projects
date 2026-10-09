import os
import json
import time

class NidsReporter:
    """Generates comprehensive JSON and HTML incident response reports for network telemetry."""

    def __init__(self, reports_dir="reports"):
        self.reports_dir = os.path.abspath(reports_dir)
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_reports(self, summary_data):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(self.reports_dir, f"nids_alerts_{timestamp}.json")
        html_path = os.path.join(self.reports_dir, f"nids_report_{timestamp}.html")

        # Save JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=4)

        # Save HTML
        html_content = self._render_html(summary_data)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return json_path, html_path

    def _render_html(self, data):
        alerts = data.get("alerts", [])
        alerts_html = ""

        if not alerts:
            alerts_html = """
            <tr>
                <td colspan="6" style="text-align: center; color: #00ff66; padding: 25px;">
                    🛡️ No malicious intrusion patterns or anomalous packets detected. Network traffic is clean.
                </td>
            </tr>
            """
        else:
            for a in alerts:
                sev = a.get("severity", "MEDIUM")
                sev_color = "#ff3366" if sev == "CRITICAL" else ("#ff9900" if sev == "HIGH" else "#00e5ff")
                alerts_html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.85rem; color: #8892b0;">{a.get('timestamp')}</td>
                    <td><strong style="color: #e6edf3;">{a.get('rule_name')}</strong></td>
                    <td><span style="background: {sev_color}22; color: {sev_color}; padding: 4px 8px; border-radius: 4px; font-weight: bold; border: 1px solid {sev_color}; font-size: 0.8rem;">{sev}</span></td>
                    <td style="font-family: monospace; font-size: 0.8rem; color: #a8b2d1;">{a.get('mitre_id')}</td>
                    <td style="font-family: monospace; font-size: 0.8rem; color: #00d4ff;">{a.get('src')} &rarr; {a.get('dest')}</td>
                    <td style="font-size: 0.85rem; color: #cbd5e1;">{a.get('description')}</td>
                </tr>
                """

        crit_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Net-Sentry NIDS Incident Report</title>
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
            --alert-orange: #ff9900;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1200px;
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
            font-size: 1.6rem;
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
            margin-top: 15px;
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
            margin-top: 40px;
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
                <h1 class="title">📡 Net-Sentry NIDS Telemetry Report</h1>
                <div style="color: var(--text-muted); margin-top: 5px;">Network Intrusion Detection & Deep Packet Analysis Log</div>
            </div>
            <div style="text-align: right; font-family: monospace; color: var(--cyber-green);">
                SESSION: {data.get('mode', 'SIMULATION')}<br>
                {data.get('timestamp')}
            </div>
        </div>

        <div class="meta-stats">
            <div class="stat-card">
                <div class="stat-label">Packets Dissected</div>
                <div class="stat-val">{data.get('packets_analyzed', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Threat Alerts</div>
                <div class="stat-val" style="color: {'var(--alert-red)' if alerts else 'var(--cyber-green)'};">
                    {len(alerts)}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical Severity</div>
                <div class="stat-val" style="color: var(--alert-red);">{crit_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Severity</div>
                <div class="stat-val" style="color: var(--alert-orange);">{high_count}</div>
            </div>
        </div>

        <h2 style="font-size: 1.2rem; margin-top: 30px;">🚨 Security Alert Logs</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Threat Rule</th>
                    <th>Severity</th>
                    <th>MITRE ATT&CK</th>
                    <th>Source &rarr; Target</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {alerts_html}
            </tbody>
        </table>

        <div class="footer">
            Generated by <strong>Net-Sentry NIDS</strong> &bull; Author: <strong>DuckWater (@TigerOneTank)</strong> &bull; CyberSecurity-_Projects
        </div>
    </div>
</body>
</html>
"""
