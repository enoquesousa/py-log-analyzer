# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Escape untrusted report fields in HTML and serialize chart data safely so a
  request path or country label cannot insert HTML or terminate a script block.
- Bundle a versioned, licensed Chart.js build in the package and generated HTML.
  Reports remain interactive offline, with a restrictive Content Security Policy
  and no runtime CDN script. Regenerate existing HTML reports to apply the fix.
- Render external terminal fields as literal text rather than Rich markup.
- CI uses read-only repository permissions and does not persist checkout
  credentials. Coverage stays in GitHub artifacts instead of an external upload.

### Fixed

- Fail on unreadable or invalid UTF-8 input before showing or exporting a
  misleading partial report. Existing output files are left unchanged on input
  failure; malformed CLF lines continue to be skipped.
- Preserve the legacy `[IP, count]` form when exporting older report data,
  alongside the current dictionary form with optional country labels.

### Changed

- Require Python 3.11 or newer and use Python 3.12 in Docker. Python 3.10 reached
  end of life on 2026-10-01. CI covers Python 3.11, 3.12, and 3.13.


## [1.0.0] - 2026-05-04

### Added
- **Modular Structure**: Reorganized the project into a professional Python package (`py_log_analyzer`).
- **CI/CD Pipeline**: GitHub Actions workflow for automated testing, linting (Ruff), security scanning (Bandit), and Docker builds.
- **Unit Tests**: Comprehensive test suite using `pytest`.
- **Performance Optimization**: Use of Python generators for memory-efficient log reading and `multiprocessing` for parallel file processing.
- **Docker Support**: Added `Dockerfile` to run the tool as an isolated container.
- **Report Export**: Support for exporting analysis results to JSON and interactive HTML dashboards with Chart.js.
- **Anomaly Detection**: Logic to identify suspicious IP activity (brute force/scrapers) based on 401/404 error counts.
- **Service Health Monitoring**: Configurable 5xx error rate thresholds with visual alerts.
- **Rich Terminal UI**: Elegant tables and panels using the `rich` library.
- **Aggregation Logic**: Top 10 IPs, Top 5 Paths, and Status Code distribution.

### Changed
- Refactored monolithic script into a modular architecture.
- Renamed project files to follow standard Python naming conventions.

## [0.1.0] - 2026-05-04

### Added
- Initial implementation of the log parser using Regular Expressions.
- Basic Command Line Interface (CLI) to process Nginx/Apache log files.
- Basic JSON output for parsed log entries.
