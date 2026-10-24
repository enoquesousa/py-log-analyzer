<div align="center">
<h1>py-log-analyzer</h1>

<p>High-performance modular CLI tool to parse, analyze and audit Nginx/Apache logs with interactive dashboards and anomaly detection.</p>

  <img src="assets/python.png" alt="py-log-analyzer banner" width="600px">

  <br>

[![CI](https://github.com/enoquesousa/py-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/enoquesousa/py-log-analyzer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat&logo=python&logoColor=white)](https://github.com/enoquesousa/py-log-analyzer/blob/master/setup.py)
[![Rich](https://img.shields.io/badge/rich-15.0%2B-green?style=flat&logo=python&logoColor=white)](https://github.com/Textualize/rich)
[![License](https://img.shields.io/github/license/enoquesousa/py-log-analyzer)](https://github.com/enoquesousa/py-log-analyzer/blob/master/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/enoquesousa/py-log-analyzer)](https://github.com/enoquesousa/py-log-analyzer/commits/master)

</div>

---

**py-log-analyzer** is a command-line tool designed for high-performance analysis of web server logs (Nginx/Apache). It features memory-efficient parsing using generators, parallel file processing via multiprocessing, and comprehensive reporting. It identifies traffic patterns, status code distributions, and suspicious IP activity (anomalies), optionally enriched with **geographic breakdown by country** (MaxMind GeoLite2 via `geoip2`), exporting results to **JSON** or interactive **HTML dashboards**. The console entry point is `py-log-analyzer`. Canonical repository: `github.com/enoquesousa/py-log-analyzer`.

## Demo (quick smoke test)

Analyze a log file and generate an interactive HTML report.

**Linux / macOS (bash)**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Run analysis with HTML report
py-log-analyzer access.log --format html --threshold 2.5
```

**Windows (PowerShell)**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# Run analysis with HTML report
py-log-analyzer access.log --format html --threshold 2.5
```

## Features

| Area | What you get |
| ---- | -------------- |
| Parsing | High-speed regex parsing of Common Log Format (CLF). |
| Performance | Memory-efficient generators and multi-core `multiprocessing` support. |
| Security | Anomaly detection for suspicious IPs (401/404 spikes). |
| GeoIP | Optional **country** labels and request totals per country using GeoLite2-Country (local `.mmdb` file). |
| Health | Service health monitoring with configurable 5xx error thresholds. |
| Export | Self-contained, offline **HTML reports** with bundled Chart.js or structured **JSON**. |
| UI | Elegant terminal tables and panels powered by `rich`. |

## Tech stack

| Component | Role |
| --------- | ---- |
| Python 3.11+ | Language and runtime |
| rich | Terminal UI and tables |
| geoip2 | MaxMind GeoIP database reader (GeoLite2-Country) |
| Chart.js | Interactive HTML visualizations |
| pytest | Unit testing and coverage |

## Prerequisites

- Python **3.11+** and `pip`. Python 3.10 reached end of life on
  [2026-10-01](https://peps.python.org/pep-0619/#lifespan); upgrade the interpreter
  before installing this version. The Docker image uses Python 3.12.
- Optional: **Docker** for containerized execution.
- Optional: **GeoLite2-Country** database (`GeoLite2-Country.mmdb`) from MaxMind for geographic analysis (see [GeoIP](#geoip-traffic-by-country)).

## Installation and usage

### From source (recommended)

```bash
git clone https://github.com/enoquesousa/py-log-analyzer.git
cd py-log-analyzer
pip install .
py-log-analyzer --help
```

### Docker

```bash
docker build -t py-log-analyzer .
docker run --rm -v "$PWD:/logs" py-log-analyzer /logs/access.log --format html
```

To use GeoIP inside Docker, mount the MaxMind database as well (path inside the container is arbitrary; adjust to match your host file):

```bash
docker run --rm -v "$PWD:/logs" -v "/path/on/host/GeoLite2-Country.mmdb:/data/GeoLite2-Country.mmdb:ro" \
  py-log-analyzer /logs/access.log --geoip-db /data/GeoLite2-Country.mmdb --format html
```

## GeoIP (traffic by country)

When you pass `--geoip-db` pointing to a local **GeoLite2-Country** MMDB file, the tool resolves each distinct client IP once and:

- Adds a **Country** column to anomaly and top-IP tables in the terminal.
- Prints **Traffic by Country** (top 15 countries by request count).
- Includes **`country_distribution`**, **`anomalies_detail`**, and per-row **`country`** in **JSON** exports.
- Adds a **Traffic by Country** chart and country column in **HTML** reports.

Private, loopback, and link-local addresses are labeled **Private / local** without querying the database.

### Obtain the free GeoLite2 database

1. Create a free MaxMind account and download **GeoLite2 Country** (`.mmdb`) from [GeoLite2 signup](https://www.maxmind.com/en/geolite2/signup).
2. Unpack the archive and note the path to `GeoLite2-Country.mmdb`.

### Examples

**Linux / macOS**

```bash
py-log-analyzer access.log --geoip-db ./GeoLite2-Country.mmdb --format html
```

**Windows (PowerShell)**

```powershell
py-log-analyzer access.log --geoip-db "D:\data\GeoLite2-Country.mmdb" --format json
```

Omit `--geoip-db` to run without geographic enrichment (same behavior as before GeoIP was added).

## Security and report privacy

This is a local CLI: it has no login, session, API listener, or runtime access
token. It reads the files you select under your operating-system permissions.
GeoIP uses a local database; the analyzer does not need a MaxMind account or
license key at runtime.

Treat logs as untrusted data. HTML export escapes report values and embeds a
versioned copy of Chart.js, so opening a newly generated report does not fetch
code from a CDN. The report's Content Security Policy restricts scripts and
outbound connections. Terminal output also treats log fields as literal text.

Reports still contain IPs, paths, and possibly query parameters carrying
credentials or personal data. Neither HTML nor JSON export automatically
redacts these values or encrypts the output. Keep reports private, review them
before sharing, and protect the source logs and output directory with suitable
file permissions. Regenerate old HTML reports to receive the output protections.

Unreadable files and invalid UTF-8 make the command fail before generating a
partial report. Lines that do not match the supported CLF pattern are still
skipped; totals count recognized entries. See the
[security and data-flow documentation](docs/security.md) for the exact limits.

## Documentation

| Document | Contents |
| -------- | -------- |
| [LICENSE](LICENSE) | MIT License |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [Security model](docs/security.md) | Request flow, credentials, report boundaries, and validation |

## CLI summary

```bash
py-log-analyzer FILES [FILES ...] [--threshold PERCENT] [--format json|html] [--geoip-db PATH]
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest --cov=py_log_analyzer
```

## Project layout

| Path | Role |
| ---- | ---- |
| `py_log_analyzer/parser.py` | Log parsing and generators |
| `py_log_analyzer/analyzer.py` | Data aggregation and anomaly detection |
| `py_log_analyzer/exporter.py` | JSON and HTML report generation |
| `py_log_analyzer/geoip.py` | GeoLite2 country lookup and aggregation |
| `py_log_analyzer/cli.py` | CLI orchestration and Terminal UI |
| `py_log_analyzer/__main__.py` | Module entry point |
| `tests/` | `pytest` suite |

## Troubleshooting

| Symptom | Likely cause | What to do |
| ------- | ------------- | ---------- |
| `ModuleNotFoundError` | Package not installed | Run `pip install .` or `pip install -e .` |
| File cannot be read | Missing file, insufficient permissions, or invalid UTF-8 | Confirm the selected paths and encoding, and grant only the access needed to read the logs. The command fails without exporting partial results. |
| `MemoryError` | Large file loading | The tool uses generators, but check if `--format html` with extreme log sizes is a factor. |
| GeoIP shows no countries / errors opening DB | Wrong path, missing file, or not the Country MMDB | Use the full path to `GeoLite2-Country.mmdb`; ensure the file is readable by the process (and mounted in Docker if applicable). |

## Study roadmap (completed)

The implementation roadmap is **finished**.

### Delivered scope

- [x] **Stage 1 — Base CLI & Parsing** — Regex-based CLF parsing and basic terminal output.
- [x] **Stage 2 — Aggregation & UI** — Top IPs/Paths/Status distributions with `rich` tables.
- [x] **Stage 3 — Anomaly & Health** — Suspicious IP detection and 5xx health alerts.
- [x] **Stage 4 — Export & Visualization** — HTML dashboards with Chart.js and JSON export.
- [x] **Stage 5 — Performance & Scale** — Generators for RAM efficiency and `multiprocessing` for parallel files.
- [x] **Stage 6 — DevOps & CI/CD** — Dockerization and GitHub Actions for automated testing/linting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).

<div align="center">

## Author

**Enoque Sousa**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/enoque-sousa-bb89aa168/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat&logo=github&logoColor=white)](https://github.com/enoquesousa)
[![Portfolio](https://img.shields.io/badge/Portfolio-FF5722?style=flat&logo=target&logoColor=white)](https://enoquesousa.vercel.app)

**[⬆ Back to Top](#py-log-analyzer)**

Made with ❤️ by [Enoque Sousa](https://github.com/enoquesousa)

**Project status:** Study project

</div>
