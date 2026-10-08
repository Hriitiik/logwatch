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


def test_web_parser():
    line = '198.51.100.20 - - [04/Oct/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
    e = parsers.parse_web_line(line)
    assert e["event"] == "web_request"
    assert e["status"] == 200
    assert e["path"] == "/index.html"


def test_web_url_decoded():
    line = '192.0.2.9 - - [04/Oct/2026:12:00:05 +0000] "GET /search?q=%27%20or%201=1-- HTTP/1.1" 200 812 "-" "Firefox/118.0"'
    assert parsers.parse_web_line(line)["path"] == "/search?q=' or 1=1--"


def test_web_garbage():
    assert parsers.parse_web_line("this is not a log line") is None
