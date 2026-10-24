# Security and data flow

## Components and execution flow

The entry point `py-log-analyzer` calls `py_log_analyzer.cli.run`. It parses the
file paths and options, optionally opens a local GeoLite2 Country database, and
uses a worker pool to process the selected log files.

| Component | Responsibility |
| --- | --- |
| `parser.py` | Read UTF-8 text and recognize the supported Common Log Format fields |
| `analyzer.py` | Count client IPs, request targets, status codes, and 401/404 events |
| `cli.py` | Merge successful results, build report data, render terminal tables, and select an export |
| `geoip.py` | Resolve distinct client IPs using the supplied local MMDB reader |
| `exporter.py` | Write JSON or a self-contained interactive HTML report |

The analyzer counts 401/404 responses as an anomaly signal. It does not verify
credentials, perform a login, or decide whether a request to the original web
server was authorized. Those decisions belong to the web server that wrote
the log. The input IP field is a reported value, not proof of a client's identity.

Each selected file must be readable as UTF-8. An I/O or decoding failure aborts
the analysis before display or export, rather than silently combining a partial
file with complete files. The process exits unsuccessfully and leaves previous
reports unchanged. A malformed line that does not match the parser is still
skipped; the report totals are counts of recognized entries, not proof that an
entire source was valid. The optional GeoIP reader is closed when processing ends.

## Authentication and credentials

There is no application account, password database, session, JWT, bearer token,
cookie, or listening HTTP endpoint. Access to input logs, the MMDB, and output
files follows the operating system's file permissions. The process runs with
the privileges of the user or container that started it.

Downloading a GeoLite2 database is a separate operation. The application reads
a local `.mmdb`; it does not request or store a MaxMind account password or
license key and does not call the MaxMind web service.

The CLF parser does not extract an Authorization header, but a request target
can contain a query-string token, signed URL, email address, or other sensitive
value. These values remain in the aggregation and exports. The application
does not provide automatic secret discovery, token rotation, revocation, or
redaction. Redact source data before analysis when required, and rotate any
credential that has already been exposed through logs or shared reports.

## Untrusted output boundaries

### HTML and chart data

Log fields and GeoIP labels are data. Text cells are HTML-escaped, and chart
values are JSON-encoded for their HTML context. A string containing HTML,
quotes, or a closing script tag must remain a value instead of becoming markup
or JavaScript. These protections apply to callers using `export_html` directly
as well as to reports built through the CLI.

The report embeds the package's versioned Chart.js asset and its license. It
does not fetch a script from a CDN or need a network connection to display
charts. Its Content Security Policy allows the intended scripts and style and
restricts network and document features. Contextual escaping remains necessary;
the policy is an additional protection, not a replacement for it.

Previously generated HTML is not retroactively changed. Regenerate it using the
corrected exporter. The checked-in demonstration is regenerated from the same
example JSON data.

### Terminal and JSON

External fields are rendered as literal terminal text, preventing Rich markup
from changing their presentation or creating links. Terminal and Unicode format
controls are shown as visible escapes rather than emitted as control sequences.
This display treatment does not rewrite the aggregated data. JSON export
preserves the report values and uses the standard JSON encoder; importing that JSON into another HTML or shell
context requires that consumer's own escaping.

### Files and availability

HTML and JSON are plaintext reports, without passwords or encryption. File
creation follows the current operating-system permissions and umask. A local
user who can read a report can read its contents. A browser's local-file policy
and the report's CSP do not protect a copied file from its recipient.

Keep input and output directories private, grant the process only the access it
needs, and inspect reports before attaching them to issues or messages. The
CLI does not upload logs or reports. Installing dependencies and downloading
the optional MMDB are separate network operations.

Streaming lines reduces the need to load a whole file at once, but counters for
distinct IPs and request targets, worker results, and exported data still grow
with the input. There is no global memory, line-length, CPU, or output-size
quota. Process untrusted large files with appropriate operating-system limits;
this CLI is not a sandbox or a network service for arbitrary callers.

## CI credentials

GitHub Actions uses a short-lived `GITHUB_TOKEN` with `contents: read` and
checkouts that do not persist credentials. Coverage is retained as a GitHub
artifact. The workflow does not use a Codecov credential or upload coverage to
Codecov. These workflow credentials are unrelated to runtime log analysis and
are not embedded in reports or the installed package.

## Validation scope

Tests use synthetic log lines, fabricated countries and IP addresses, temporary
files, and a fake local GeoIP reader. They cover output injection, data
round-tripping, missing or undecodable input, and preservation of output on
failure. They do not require production logs, a MaxMind account, or provider
credentials. Packaging checks verify that the bundled chart asset is available
when a wheel is installed outside the source checkout.

Python 3.11 is the minimum supported version. Python 3.10 reached end of life on
[2026-10-01](https://peps.python.org/pep-0619/#lifespan), so it no longer receives
upstream security updates.
