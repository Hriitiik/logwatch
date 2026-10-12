import json
from datetime import UTC, datetime

from logwatch.engine import summarize
from logwatch.report import alerts_to_json, render_html
from logwatch.rules import Alert


def make_alert(detail="15 failures", ip="203.0.113.5"):
    return Alert(
        rule="ssh_bruteforce",
        severity="high",
        attack_id="T1110.001",
        ip=ip,
        ts=datetime(2026, 10, 4, 12, 0, tzinfo=UTC),
        detail=detail,
    )


def test_json_roundtrip(tmp_path):
    p = tmp_path / "r.json"
    alerts_to_json([make_alert()], str(p))
    data = json.loads(p.read_text())
    assert data[0]["ip"] == "203.0.113.5"
    assert data[0]["ts"] == "2026-10-04T12:00:00+00:00"


def test_html_contains_alert(tmp_path):
    alerts = [make_alert()]
    out = tmp_path / "r.html"
    render_html(alerts, summarize(alerts), str(out))
    html = out.read_text()
    assert "203.0.113.5" in html and "T1110.001" in html


def test_html_escape_attacker_content(tmp_path):
    alerts = [make_alert(detail="<script>alert(1)</script>")]
    out = tmp_path / "r.html"
    render_html(alerts, summarize(alerts), str(out))
    html = out.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_with_no_alerts(tmp_path):
    out = tmp_path / "r.html"
    render_html([], summarize([]), str(out))
    assert "No alerts" in out.read_text()
