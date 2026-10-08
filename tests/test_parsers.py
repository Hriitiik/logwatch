from pathlib import Path

from logwatch import parsers


def test_failed_login():
    line = "Oct  2 10:15:41 srv sshd[812]: Failed password for root from 203.0.113.5 port 5522 ssh2"
    e = parsers.parse_auth_line(line, 2026)
    assert e["event"] == "failed_login"
    assert e["ip"] == "203.0.113.5"
    assert e["user"] == "root"


def test_events_detected():
    path = Path(__file__).parent.parent / "samples" / "auth.log"
    events = parsers.parse_auth_file(path)
    assert len(events) == 3


def test_garbage_returns_none():
    assert parsers.parse_auth_line("not a log line", 2026) is None
