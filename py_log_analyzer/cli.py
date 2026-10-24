import argparse
import multiprocessing
import unicodedata
from collections import Counter

import geoip2.database
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import detect_anomalies, get_status_categories, process_file
from .exporter import export_html, export_json
from .geoip import enrich_ip_geo
from .parser import LogReadError


def _terminal_text(value):
    """Render external fields literally and expose terminal/format controls.

    Only presentation is changed: the aggregate and exported data retain their
    original strings. Text avoids Rich markup and hyperlink interpretation.
    """
    visible = "".join(character.encode("unicode_escape").decode("ascii") if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} else character for character in value)
    return Text(visible)


def build_report_data(merged_data, error_threshold_5xx, geo_reader=None):
    total_requests = merged_data["total_count"]
    ip_counts = merged_data["ip_counts"]
    url_counts = merged_data["url_counts"]
    status_counts = merged_data["status_counts"]
    suspicious_ips = merged_data["suspicious_ips"]

    status_categories = get_status_categories(status_counts)
    anomalies = detect_anomalies(suspicious_ips)

    total_errors = status_categories["4xx (Client Error)"] + status_categories["5xx (Server Error)"]
    error_rate = (total_errors / total_requests) * 100 if total_requests else 0.0
    rate_5xx = (status_categories["5xx (Server Error)"] / total_requests) * 100 if total_requests else 0.0
    is_critical = rate_5xx >= error_threshold_5xx

    top_ips = [{"ip": ip, "requests": cnt, "country": None} for ip, cnt in ip_counts.most_common(10)]

    report_data = {
        "total_requests": total_requests,
        "error_rate": error_rate,
        "rate_5xx": rate_5xx,
        "threshold": error_threshold_5xx,
        "is_critical": is_critical,
        "status_distribution": status_categories,
        "top_ips": top_ips,
        "top_paths": url_counts.most_common(5),
        "anomalies": anomalies,
        "country_distribution": None,
        "anomalies_detail": None,
        "geo_enabled": False,
    }

    if geo_reader is not None:
        geo = enrich_ip_geo(geo_reader, ip_counts, anomalies)
        report_data["top_ips"] = geo["top_ips"]
        report_data["country_distribution"] = geo["country_distribution"]
        report_data["anomalies_detail"] = geo["anomalies_detail"]
        report_data["geo_enabled"] = True

    return report_data


def display_summary(merged_data, error_threshold_5xx, export_format=None, geo_reader=None):
    console = Console()
    total_requests = merged_data["total_count"]

    if total_requests == 0:
        console.print("[bold yellow]No valid log entries found to analyze.[/bold yellow]")
        return

    report_data = build_report_data(merged_data, error_threshold_5xx, geo_reader)

    if export_format == "json":
        export_json(report_data, "report.json")
        console.print("[bold green]Report exported to report.json[/bold green]")
    elif export_format == "html":
        export_html(report_data, "report.html")
        console.print("[bold green]Report exported to report.html[/bold green]")

    anomalies = report_data["anomalies"]

    if anomalies:
        table = Table(
            title="[bold red]Anomaly Detected: Suspicious IP Activity[/bold red]",
            border_style="red",
        )
        table.add_column("IP Address", style="bright_red")
        table.add_column("401/404 Errors", justify="right")
        if report_data["geo_enabled"]:
            table.add_column("Country", style="yellow")
            detail_by_ip = {row["ip"]: row["country"] for row in report_data["anomalies_detail"]}
            for ip, count in anomalies.items():
                table.add_row(_terminal_text(ip), str(count), _terminal_text(detail_by_ip.get(ip, "Unknown")))
        else:
            for ip, count in anomalies.items():
                table.add_row(_terminal_text(ip), str(count))
        console.print(table)
    else:
        console.print("[bold green]No IP anomalies detected (threshold > 50 errors).[/bold green]")

    if report_data["is_critical"]:
        console.print(
            Panel(
                f"[bold white on red] CRITICAL SERVICE HEALTH [/bold white on red]\n5xx Error Rate: {report_data['rate_5xx']:.2f}% (Threshold: {report_data['threshold']}%)",
                expand=False,
            )
        )

    ip_table = Table(title="Top 10 IP Addresses")
    ip_table.add_column("IP Address", style="cyan")
    ip_table.add_column("Requests", justify="right", style="magenta")
    if report_data["geo_enabled"]:
        ip_table.add_column("Country", style="yellow")
        for row in report_data["top_ips"]:
            ip_table.add_row(_terminal_text(row["ip"]), str(row["requests"]), _terminal_text(row["country"]))
    else:
        for row in report_data["top_ips"]:
            ip_table.add_row(_terminal_text(row["ip"]), str(row["requests"]))

    geo_table = None
    if report_data["geo_enabled"] and report_data["country_distribution"]:
        geo_table = Table(title="Traffic by Country (requests)")
        geo_table.add_column("Country", style="cyan")
        geo_table.add_column("Requests", justify="right", style="magenta")
        for country, cnt in list(report_data["country_distribution"].items())[:15]:
            geo_table.add_row(_terminal_text(country), str(cnt))

    status_table = Table(title="Requests by Status Code")
    status_table.add_column("Category", style="green")
    status_table.add_column("Count", justify="right", style="yellow")
    for cat, count in report_data["status_distribution"].items():
        status_table.add_row(cat, str(count))

    url_table = Table(title="Top 5 Accessed Paths")
    url_table.add_column("Path", style="blue")
    url_table.add_column("Requests", justify="right", style="magenta")
    for url, count in report_data["top_paths"]:
        url_table.add_row(_terminal_text(url), str(count))

    console.print(ip_table)
    if geo_table is not None:
        console.print(geo_table)
    console.print(status_table)
    console.print(url_table)

    console.print(f"\n[bold green]Total requests processed: {total_requests}[/bold green]")
    console.print(f"[bold]Total Error Rate: {report_data['error_rate']:.2f}%[/bold]")


def run():
    parser = argparse.ArgumentParser(description="Analyze Nginx/Apache log files with performance optimizations.")
    parser.add_argument("files", nargs="+", help="Path to one or more log files")
    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        help="5xx error threshold for critical health alert (default: 5.0%%)",
    )
    parser.add_argument("--format", choices=["json", "html"], help="Export format for the analysis report")
    parser.add_argument(
        "--geoip-db",
        metavar="PATH",
        help="Path to MaxMind GeoLite2-Country.mmdb (free DB from https://www.maxmind.com/en/geolite2/signup ). Enables country labels and traffic-by-country breakdown.",
    )
    args = parser.parse_args()

    geo_reader = None
    if args.geoip_db:
        geo_reader = geoip2.database.Reader(args.geoip_db)

    try:
        with multiprocessing.Pool() as pool:
            results = pool.map(process_file, args.files)

        merged_data = {
            "ip_counts": Counter(),
            "url_counts": Counter(),
            "status_counts": Counter(),
            "suspicious_ips": Counter(),
            "total_count": 0,
        }

        for res in results:
            merged_data["ip_counts"].update(res["ip_counts"])
            merged_data["url_counts"].update(res["url_counts"])
            merged_data["status_counts"].update(res["status_counts"])
            merged_data["suspicious_ips"].update(res["suspicious_ips"])
            merged_data["total_count"] += res["total_count"]

        display_summary(merged_data, args.threshold, args.format, geo_reader)
    except LogReadError:
        parser.exit(2, "error: Could not read all input log files as UTF-8; no report was generated.\n")
    finally:
        if geo_reader is not None:
            geo_reader.close()
