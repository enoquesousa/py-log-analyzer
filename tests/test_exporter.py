import base64
import copy
import hashlib
import json
from html.parser import HTMLParser
from importlib.resources import files

import pytest

from py_log_analyzer.analyzer import get_status_categories, process_file
from py_log_analyzer.exporter import export_html, export_json


class ReportDocument(HTMLParser):
    """Inspect the browser-facing HTML structure without executing its scripts."""

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.scripts = []
        self.styles = []
        self.cells = []
        self._script = None
        self._style = None
        self._cell = None
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if tag == "script":
            self._script = {"attributes": attributes, "text": ""}
            self.scripts.append(self._script)
        if tag == "style":
            self._style = []
        if tag == "td":
            self._cell = []

    def handle_endtag(self, tag):
        if tag == "script":
            self._script = None
        if tag == "style" and self._style is not None:
            self.styles.append("".join(self._style))
            self._style = None
        if tag == "td" and self._cell is not None:
            self.cells.append("".join(self._cell))
            self._cell = None

    def handle_data(self, data):
        if self._script is not None:
            self._script["text"] += data
        if self._style is not None:
            self._style.append(data)
        if self._cell is not None:
            self._cell.append(data)

    def chart_data(self):
        blocks = [script for script in self.scripts if script["attributes"].get("id") == "chart-data"]
        assert len(blocks) == 1
        assert blocks[0]["attributes"]["type"] == "application/json"
        return json.loads(blocks[0]["text"])

    def assert_no_injected_elements(self):
        assert not any(tag in {"svg", "img", "iframe", "object", "base", "form"} for tag, _ in self.elements)
        assert not any(name.lower().startswith("on") for _, attrs in self.elements for name in attrs)


def report(**overrides):
    data = {
        "total_requests": 1,
        "error_rate": 0.0,
        "rate_5xx": 0.0,
        "threshold": 5.0,
        "is_critical": False,
        "anomalies": {},
        "status_distribution": {"2xx (Success)": 1},
        "top_paths": [("/index.html", 1)],
        "top_ips": [{"ip": "198.51.100.7", "requests": 1}],
        "geo_enabled": False,
        "country_distribution": {},
    }
    data.update(overrides)
    return data


def document(tmp_path, data):
    output = tmp_path / "report.html"
    export_html(data, output)
    return ReportDocument(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("ip", "path"),
    [
        ("198.51.100.7", "/<img/src=x/onerror=globalThis.__pylogInjected=true>"),
        ("198.51.100.7<svg/onload=globalThis.__pylogInjected=true>", "/index.html"),
    ],
)
def test_parser_accepted_log_values_remain_text(tmp_path, ip, path):
    # These are synthetic tokens accepted by the existing CLF parser. The
    # exporter must not interpret a token as markup, even if it is not an IP.
    log = tmp_path / "synthetic.log"
    log.write_text(f'{ip} - - [10/Oct/2000:13:55:36 -0700] "GET {path} HTTP/1.1" 200 2326\n', encoding="utf-8")
    counts = process_file(log)
    assert counts["total_count"] == 1
    assert list(counts["ip_counts"]) == [ip]
    assert list(counts["url_counts"]) == [path]
    data = report(
        total_requests=counts["total_count"],
        status_distribution=get_status_categories(counts["status_counts"]),
        top_paths=counts["url_counts"].most_common(5),
        top_ips=[{"ip": address, "requests": count} for address, count in counts["ip_counts"].most_common(10)],
    )
    doc = document(tmp_path, data)
    doc.assert_no_injected_elements()
    assert ip in doc.cells
    assert path in doc.cells


def test_country_cannot_inject_markup_or_end_a_script(tmp_path):
    country = "</script><svg/onload=globalThis.__pylogInjected=true>"
    doc = document(
        tmp_path,
        report(
            geo_enabled=True,
            country_distribution={country: 1},
            top_ips=[{"ip": "198.51.100.7", "requests": 1, "country": country}],
        ),
    )
    doc.assert_no_injected_elements()
    assert country in doc.cells
    assert doc.chart_data()["country_labels"] == [country]
    assert doc.chart_data()["country_values"] == [1]


def test_status_labels_cannot_end_a_script_and_use_json_values(tmp_path):
    label = "</ScRiPt><svg/onload=globalThis.__pylogInjected=true> & ' \" \u2028 \u2029 Brasil"
    data = report(status_distribution={label: 1, "optional": None, "boolean": True})
    doc = document(tmp_path, data)
    doc.assert_no_injected_elements()
    assert doc.chart_data()["status_labels"] == list(data["status_distribution"])
    assert doc.chart_data()["status_values"] == [1, None, True]


def test_export_json_preserves_data_and_html_does_not_mutate_it(tmp_path):
    payload = "</script> & < > ' \" /café/日本語 \u2028 \u2029"
    data = report(top_paths=[(payload, 2)], top_ips=[{"ip": payload, "requests": 2, "country": payload}])
    original = copy.deepcopy(data)
    output = tmp_path / "report.json"
    export_json(data, output)
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(json.dumps(original))
    doc = document(tmp_path, data)
    doc.assert_no_injected_elements()
    assert payload in doc.cells
    assert data == original


def test_every_displayed_value_is_escaped_even_when_passed_directly(tmp_path):
    payload = "<svg/onload=globalThis.__pylogInjected=true>&'\""
    data = report(
        total_requests=payload,
        threshold=payload,
        top_paths=[(payload, payload)],
        top_ips=[{"ip": payload, "requests": payload, "country": payload}],
        geo_enabled=True,
        country_distribution={"Synthetic country": 1},
    )
    doc = document(tmp_path, data)
    doc.assert_no_injected_elements()
    assert doc.cells.count(payload) == 5


@pytest.mark.parametrize("geo_enabled", [False, True])
def test_report_is_offline_and_csp_hashes_match_exact_script_and_style_bytes(tmp_path, geo_enabled):
    doc = document(tmp_path, report(geo_enabled=geo_enabled, country_distribution={"Synthetic country": 1}))
    policies = [attrs["content"] for tag, attrs in doc.elements if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"]
    assert len(policies) == 1
    directives = {parts[0]: parts[1:] for item in policies[0].split(";") if (parts := item.strip().split())}
    assert directives["default-src"] == ["'none'"]
    assert directives["connect-src"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["form-action"] == ["'none'"]
    assert "'unsafe-inline'" not in policies[0]
    assert "'unsafe-eval'" not in policies[0]

    def source_hash(source):
        digest = base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")
        return f"'sha256-{digest}'"

    executable = [script for script in doc.scripts if script["attributes"].get("type") != "application/json"]
    assert len(executable) == 2
    assert set(directives["script-src"]) == {source_hash(script["text"]) for script in executable}
    assert len(doc.styles) == 1
    assert directives["style-src"] == [source_hash(doc.styles[0])]
    assert all("src" not in script["attributes"] for script in doc.scripts)
    assert not any("href" in attrs or "src" in attrs or "style" in attrs for _, attrs in doc.elements)
    assert "Chart.js v4.6.1" in executable[0]["text"]
    assert "Permission is hereby granted" in executable[0]["text"]
    assert "Jukka Kurkela" in executable[0]["text"]
    assert "sourceMappingURL" not in executable[0]["text"]
    assert len([tag for tag, _ in doc.elements if tag == "canvas"]) == (2 if geo_enabled else 1)


def test_empty_report_still_has_valid_chart_data(tmp_path):
    doc = document(tmp_path, report(total_requests=0, status_distribution={}, top_paths=[], top_ips=[], geo_enabled=True))
    assert doc.chart_data() == {"status_labels": [], "status_values": [], "country_labels": [], "country_values": []}
    assert len([tag for tag, _ in doc.elements if tag == "canvas"]) == 1


def test_legacy_ip_pairs_are_preserved_and_escaped(tmp_path):
    ip = "198.51.100.7<svg/onload=globalThis.__pylogInjected=true>"
    data = report(top_ips=[[ip, 2], ["198.51.100.8", 1]])
    before = copy.deepcopy(data)
    doc = document(tmp_path, data)
    doc.assert_no_injected_elements()
    assert ip in doc.cells
    assert "198.51.100.8" in doc.cells
    assert data == before


def test_country_chart_keeps_original_order_and_twelve_item_limit(tmp_path):
    countries = {f"Country {index}": 20 - index for index in range(15)}
    doc = document(tmp_path, report(geo_enabled=True, country_distribution=countries))
    assert doc.chart_data()["country_labels"] == list(countries)[:12]
    assert doc.chart_data()["country_values"] == list(countries.values())[:12]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_chart_values_are_rejected_instead_of_emitting_invalid_json(tmp_path, value):
    output = tmp_path / "report.html"
    with pytest.raises(ValueError, match="Out of range float values"):
        export_html(report(status_distribution={"Synthetic": value}), output)
    assert not output.exists()


def test_packaged_chart_assets_match_the_recorded_upstream_integrity():
    assets = files("py_log_analyzer").joinpath("assets")
    metadata = json.loads(assets.joinpath("chartjs-integrity.json").read_text(encoding="utf-8"))
    assert metadata["name"] == "chart.js"
    assert metadata["version"] == "4.6.1"
    assert metadata["tarball"] == "https://registry.npmjs.org/chart.js/-/chart.js-4.6.1.tgz"
    assert metadata["npm_integrity"] == "sha512-hJyniucsFmq//EvXYvJ6c6mahPoI3kaxdjVH8awTaJ/fDNWeSqqqArixMJWkWNN6fcYvPU3HneSANFNYtRi61g=="
    for name, record in metadata["files"].items():
        content = assets.joinpath(name).read_bytes()
        assert len(content) == record["bytes"]
        assert hashlib.sha256(content).hexdigest() == record["sha256"]
    color = metadata["bundled_color"]
    assert hashlib.sha256(assets.joinpath(color["license_file"]).read_bytes()).hexdigest() == color["license_sha256"]
