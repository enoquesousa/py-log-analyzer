import re


class LogReadError(Exception):
    """A log could not be read completely; partial aggregates must not be used."""


def parse_log_line(line):
    """Common Log Format (CLF) regex parser."""
    regex = r'(?P<ip>\S+) .*?\[(?P<timestamp>.*?)\] "(?P<method>\S+)\s+(?P<url>\S+)\s+.*?"\s+(?P<status>\d{3})'
    match = re.search(regex, line)
    if match:
        return match.groupdict()
    return None


def log_generator(file_path):
    """Yield recognized entries; fail if the file cannot be read fully as UTF-8."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    yield parsed
    except (OSError, UnicodeError):
        # Keep this exception picklable for multiprocessing. Do not include the
        # file name, log bytes or the original exception text in its message.
        raise LogReadError("Could not read a log file completely as UTF-8.") from None
