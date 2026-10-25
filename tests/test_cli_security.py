import copy
import io
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from py_log_analyzer import cli
from py_log_analyzer.analyzer import process_file
from py_log_analyzer.parser import LogReadError, log_generator

LINE = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /synthetic HTTP/1.1" 200 1\n'
CLI_READ_ERROR = "error: Could not read all input log files as UTF-8; no report was generated.\n"


def _merged_data(ip="127.0.0.1", path="/synthetic", errors=0):
    count = max(errors, 1)
    return {
        "ip_counts": Counter({ip: count}),
        "url_counts": Counter({path: count}),
        "status_counts": Counter({"401" if errors else "200": count}),
        "suspicious_ips": Counter({ip: errors}) if errors else Counter(),
        "total_count": count,
    }


def _capture_terminal(monkeypatch):
    output = io.StringIO()
    console = Console(file=output, force_terminal=True, color_system="standard", width=240, height=80, highlight=False)
    monkeypatch.setattr(cli, "Console", lambda: console)
    return output


@pytest.mark.parametrize(
    "path",
    [
        "/[/]",
        "/[bold]literal[/bold]",
        "/[link=https://example.invalid]synthetic[/link]",
        "/literal\\[bold]suffix",
    ],
)
def test_log_markup_is_literal_in_the_real_summary(monkeypatch, path):
    output = _capture_terminal(monkeypatch)

    cli.display_summary(_merged_data(path=path), 5.0)

    assert path in output.getvalue()
    assert "\x1b]8;" not in output.getvalue()


@pytest.mark.parametrize(
    ("path", "visible"),
    [
        ("/A\x1b[2JB", r"/A\x1b[2JB"),
        ("/\x1b]8;;https://example.invalid\x1b\\label\x1b]8;;\x1b\\", r"/\x1b]8;;https://example.invalid\x1b\label\x1b]8;;\x1b" + "\\"),
        ("/one\rtwo\bthree\afour", r"/one\rtwo\x08three\x07four"),
        ("/one\x9btwo", r"/one\x9btwo"),
        ("/one\u202etwo\u2066three\u2069", r"/one\u202etwo\u2066three\u2069"),
        ("/one\u2028two\u2029three", r"/one\u2028two\u2029three"),
    ],
)
def test_terminal_controls_are_visible_text_not_terminal_commands(monkeypatch, path, visible):
    output = _capture_terminal(monkeypatch)

    cli.display_summary(_merged_data(path=path), 5.0)

    rendered = output.getvalue()
    assert visible in rendered
    assert "\x1b[2J" not in rendered
    assert "\x1b]8;" not in rendered
    for control in ["\r", "\b", "\a", "\x9b", "\u202e", "\u2066", "\u2069", "\u2028", "\u2029"]:
        assert control not in rendered


def test_external_ip_and_country_cells_are_literal_and_exported_data_is_unchanged(monkeypatch, tmp_path):
    ip = "[link=https://example.invalid]ip[/link]\x1b[2J"
    path = "/[bold]path[/bold]?access_token=SYNTHETIC_ONLY\u202e"
    country = "[/]Country\x1b]8;;https://example.invalid\x1b\\"
    data = _merged_data(ip=ip, path=path, errors=51)
    original = copy.deepcopy(data)
    reader = MagicMock()
    reader.country.return_value.country.name = country
    output = _capture_terminal(monkeypatch)
    monkeypatch.chdir(tmp_path)

    cli.display_summary(data, 5.0, "json", reader)

    rendered = output.getvalue()
    assert "[link=https://example.invalid]ip[/link]\\x1b[2J" in rendered
    assert "[/]Country\\x1b]8;;https://example.invalid\\x1b\\" in rendered
    assert "[bold]path[/bold]?access_token=SYNTHETIC_ONLY\\u202e" in rendered
    assert "\x1b]8;" not in rendered
    assert "\x1b[2J" not in rendered
    assert data == original
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["top_ips"][0]["ip"] == ip
    assert report["top_ips"][0]["country"] == country
    assert report["anomalies"][ip] == 51
    assert report["top_paths"][0][0] == path


def test_invalid_utf8_after_valid_entries_fails_instead_of_returning_partial_counts(tmp_path, capsys):
    log = tmp_path / "SYNTHETIC_PRIVATE_FILENAME.log"
    log.write_bytes((LINE * 1_000).encode() + b"\xff\n")

    with pytest.raises(LogReadError) as failure:
        process_file(log)

    assert str(failure.value) == "Could not read a log file completely as UTF-8."
    assert capsys.readouterr().err == ""


def test_a_late_io_error_propagates_without_exception_details(monkeypatch):
    class InterruptedLog:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __iter__(self):
            yield LINE
            raise OSError("SYNTHETIC_PRIVATE_IO_DETAIL")

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: InterruptedLog())
    entries = log_generator("synthetic.log")
    assert next(entries)["url"] == "/synthetic"

    with pytest.raises(LogReadError) as failure:
        next(entries)

    assert str(failure.value) == "Could not read a log file completely as UTF-8."
    assert failure.value.__suppress_context__ is True


def test_nonmatching_lines_remain_skipped_without_changing_recognized_counts(tmp_path):
    log = tmp_path / "mixed.log"
    log.write_text("not a CLF entry\n" + LINE + "another invalid line\n" + LINE, encoding="utf-8")

    data = process_file(log)

    assert data["total_count"] == 2
    assert data["url_counts"] == Counter({"/synthetic": 2})


def _run_cli(tmp_path, arguments):
    # Exercise run(), the real parser, pickling and real worker processes. Limit
    # only the worker count so the test does not depend on the host CPU count.
    runner = """
import multiprocessing
from py_log_analyzer.cli import run

original_pool = multiprocessing.Pool

def small_pool(*args, **kwargs):
    return original_pool(processes=2)

if __name__ == '__main__':
    multiprocessing.Pool = small_pool
    run()
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    return subprocess.run(
        [sys.executable, "-c", runner, *arguments],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("export_format", ["json", "html"])
@pytest.mark.parametrize("failure_kind", ["missing", "invalid_utf8"])
def test_cli_read_failure_keeps_existing_report_and_exits_nonzero(tmp_path, export_format, failure_kind):
    valid = tmp_path / "valid.log"
    valid.write_text(LINE, encoding="utf-8")
    failed = tmp_path / "SYNTHETIC_PRIVATE_FILENAME.log"
    if failure_kind == "invalid_utf8":
        failed.write_bytes((LINE * 1_000).encode() + b"\xff\n")
    report = tmp_path / f"report.{export_format}"
    report.write_bytes(b"EXISTING_REPORT_MUST_REMAIN")

    result = _run_cli(tmp_path, [str(valid), str(failed), "--format", export_format])

    assert result.returncode == 2
    assert result.stderr == CLI_READ_ERROR
    assert result.stdout == ""
    assert report.read_bytes() == b"EXISTING_REPORT_MUST_REMAIN"


def test_cli_success_still_exports_all_recognized_entries(tmp_path):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text(LINE, encoding="utf-8")
    second.write_text(LINE + "not a log entry\n", encoding="utf-8")

    result = _run_cli(tmp_path, [str(first), str(second), "--format", "json"])

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["total_requests"] == 2


def test_geoip_reader_closes_when_a_worker_cannot_read_a_log(monkeypatch, capsys):
    reader = MagicMock()
    monkeypatch.setattr(cli.geoip2.database, "Reader", lambda path: reader)
    pool = MagicMock()
    pool.__enter__.return_value.map.side_effect = LogReadError("Could not read a log file completely as UTF-8.")
    monkeypatch.setattr(cli.multiprocessing, "Pool", lambda: pool)
    summary = MagicMock()
    monkeypatch.setattr(cli, "display_summary", summary)
    monkeypatch.setattr(sys, "argv", ["py-log-analyzer", "missing.log", "--geoip-db", "synthetic.mmdb"])

    with pytest.raises(SystemExit) as failure:
        cli.run()

    assert failure.value.code == 2
    reader.close.assert_called_once_with()
    summary.assert_not_called()
    assert capsys.readouterr().err == CLI_READ_ERROR
