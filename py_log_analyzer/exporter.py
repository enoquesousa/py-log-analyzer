"""JSON export and a self-contained HTML report with inert, escaped log data."""

import base64
import hashlib
import json
from html import escape
from importlib.resources import files

_CHART_ASSET = "chart.umd-4.6.1.js"

_STYLE = """
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; }
.container { max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1, h2 { color: #333; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
.card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; }
.full-width { grid-column: span 2; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; overflow-wrap: anywhere; }
th { background-color: #f8f8f8; }
.alert { background-color: #ffebee; border-left: 5px solid #f44336; padding: 10px; margin-bottom: 20px; color: #c62828; }
.health-panel { background-color: #e8f5e9; border-left: 5px solid #4caf50; padding: 15px; margin-bottom: 20px; }
.health-critical { background-color: #ffebee; border-left: 5px solid #f44336; }
"""

# Executable code is static. Log-derived labels and counts are parsed only from
# the separate application/json data block, never interpolated into JavaScript.
_CHART_SCRIPT = """
(() => {
    'use strict';
    const data = JSON.parse(document.getElementById('chart-data').textContent);
    new Chart(document.getElementById('statusChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: data.status_labels,
            datasets: [{
                data: data.status_values,
                backgroundColor: ['#4caf50', '#2196f3', '#ff9800', '#f44336']
            }]
        }
    });
    const countryCanvas = document.getElementById('countryChart');
    if (countryCanvas) {
        new Chart(countryCanvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.country_labels,
                datasets: [{
                    label: 'Requests',
                    data: data.country_values,
                    backgroundColor: '#2196f3'
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: { legend: { display: false } }
            }
        });
    }
})();
"""


def _html(value):
    """Keep every displayed value in the HTML text context."""
    return escape(str(value), quote=True)


def _script_json(value):
    """Serialize data without letting HTML's raw-text parser end the block.

    application/json is inert, but a literal </script> still closes its element.
    JSON escapes preserve the original strings when JSON.parse reads the block.
    """
    return json.dumps(value, ensure_ascii=True, allow_nan=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _hash_source(source):
    digest = base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")
    return f"'sha256-{digest}'"


def _chart_source():
    assets = files("py_log_analyzer").joinpath("assets")
    license_text = assets.joinpath("Chart.js-LICENSE.md").read_text(encoding="utf-8")
    color_license = assets.joinpath("kurkle-color-LICENSE.md").read_text(encoding="utf-8")
    source = assets.joinpath(_CHART_ASSET).read_text(encoding="utf-8")
    # Keep vendored bytes intact on disk. The standalone report has no source
    # map, so omit its development-only reference when embedding the library.
    source = "".join(line for line in source.splitlines(keepends=True) if not line.startswith("//# sourceMappingURL="))
    source = f"/*\n{license_text}\nBundled @kurkle/color:\n{color_license}\n*/\n{source}"
    if "</script" in source.lower():
        raise ValueError("The bundled chart library is not safe to embed in HTML")
    return source


def export_json(report_data, output_file):
    """Export analysis results to a JSON file."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)


def export_html(report_data, output_file):
    """Export a single offline HTML file; report data never becomes executable code."""
    geo_enabled = bool(report_data.get("geo_enabled") and report_data.get("country_distribution"))
    status = report_data["status_distribution"]
    countries = report_data.get("country_distribution", {}) if geo_enabled else {}
    country_labels = list(countries)[:12]
    chart_data = _script_json(
        {
            "status_labels": list(status),
            "status_values": list(status.values()),
            "country_labels": country_labels,
            "country_values": [countries[label] for label in country_labels],
        }
    )
    chart_source = _chart_source()
    # Hash only trusted, static code and style. CSP is an additional boundary;
    # HTML escaping and safe JSON serialization protect the data independently.
    policy = (
        "default-src 'none'; "
        f"script-src {_hash_source(chart_source)} {_hash_source(_CHART_SCRIPT)}; "
        f"style-src {_hash_source(_STYLE)}; "
        "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    )
    top_ips_header = "<th>IP Address</th><th>Requests</th>" + ("<th>Country</th>" if geo_enabled else "")
    top_ips_rows = []
    for row in report_data["top_ips"]:
        if isinstance(row, dict):
            ip, requests, country = row["ip"], row["requests"], row.get("country") or ""
        else:
            # Reports produced before GeoIP support stored [IP, count] pairs.
            ip, requests = row
            country = ""
        country_cell = f"<td>{_html(country)}</td>" if geo_enabled else ""
        top_ips_rows.append(f"<tr><td>{_html(ip)}</td><td>{_html(requests)}</td>{country_cell}</tr>")
    top_paths_rows = "".join(f"<tr><td>{_html(path)}</td><td>{_html(count)}</td></tr>" for path, count in report_data["top_paths"])
    country_chart = '<div class="card"><h2>Traffic by Country</h2><canvas id="countryChart"></canvas></div>' if geo_enabled else ""
    geo_note = "<p><strong>GeoIP:</strong> MaxMind GeoLite2 Country (traffic shown by country)</p>" if geo_enabled else ""
    critical_class = "health-critical" if report_data["is_critical"] else ""
    health = "CRITICAL" if report_data["is_critical"] else "HEALTHY"
    ips_class = "" if geo_enabled else "full-width"
    anomaly_note = f'<div class="alert"><strong>Anomalies Detected:</strong> Suspicious activity from {_html(len(report_data["anomalies"]))} IP(s).</div>' if report_data["anomalies"] else ""

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="{_html(policy)}">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <title>Log Analysis Report</title>
    <style>{_STYLE}</style>
</head>
<body>
    <div class="container">
        <h1>Log Analysis Report</h1>
{geo_note}
        <div class="health-panel {critical_class}">
            <strong>Service Health:</strong> {health}<br>
            Total Requests: {_html(report_data['total_requests'])}<br>
            Global Error Rate: {_html(f"{report_data['error_rate']:.2f}")}%<br>
            5xx Rate: {_html(f"{report_data['rate_5xx']:.2f}")}% (Threshold: {_html(report_data['threshold'])}%)
        </div>
{anomaly_note}
        <div class="grid">
            <div class="card">
                <h2>Requests by Status</h2>
                <canvas id="statusChart"></canvas>
            </div>
            <div class="card">
                <h2>Top 5 Paths</h2>
                <table>
                    <thead><tr><th>Path</th><th>Requests</th></tr></thead>
                    <tbody>{top_paths_rows}</tbody>
                </table>
            </div>
        </div>
        <div class="grid">
{country_chart}
            <div class="card {ips_class}">
                <h2>Top 10 IP Addresses</h2>
                <table>
                    <thead><tr>{top_ips_header}</tr></thead>
                    <tbody>{''.join(top_ips_rows)}</tbody>
                </table>
            </div>
        </div>
    </div>
    <script>{chart_source}</script>
    <script id="chart-data" type="application/json">{chart_data}</script>
    <script>{_CHART_SCRIPT}</script>
</body>
</html>
"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_template)
