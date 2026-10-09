from datetime import datetime, timedelta, timezone
from pathlib import Path

from logwatch import engine
from logwatch.rules import Alert


def test_load_events():
    auth_path = Path(__file__).parent.parent / "samples" / "auth.log"
    web_path = Path(__file__).parent.parent / "samples" / "access.log"
    events = engine.load_events(auth_path, web_path)
    assert len(events["auth"]) == 3
    assert len(events["web"]) == 3


def test_run_rules():
    start = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc)

    event_by_source = {
        "auth": [
            {
                "ts": start + timedelta(seconds=i),
                "source": "auth",
                "event": "failed_login",
                "ip": "192.168.1.10",
                "user": "admin",
            }
            for i in range(15)
        ],
        "web": [],
    }

    alerts = engine.run_rules(event_by_source)

    assert isinstance(alerts, list)
    assert len(alerts) > 0


def test_sorted_alerts_different_severities():
    alerts = [
        Alert(
            rule="web_injection_probes",
            severity="medium",
            attack_id="T1190",
            ip="192.168.1.20",
            ts=datetime(2026, 10, 9, 10, 2, tzinfo=timezone.utc),
            detail="Possible SQL injection",
        ),
        Alert(
            rule="ssh_bruteforce",
            severity="high",
            attack_id="T1110",
            ip="192.168.1.10",
            ts=datetime(2026, 10, 9, 10, 1, tzinfo=timezone.utc),
            detail="Too many failed logins",
        ),
        Alert(
            rule="login_after_failures",
            severity="critical",
            attack_id="T1078",
            ip="192.168.1.30",
            ts=datetime(2026, 10, 9, 10, 3, tzinfo=timezone.utc),
            detail="Successful login after repeated failures",
        ),
        Alert(
            rule="scanner_user_agents",
            severity="low",
            attack_id="T1595",
            ip="192.168.1.40",
            ts=datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc),
            detail="Suspicious scanner user agent",
        ),
    ]
    sorted_alerts = engine.sort_alerts(alerts)

    assert [a.severity for a in sorted_alerts] == ["critical", "high", "medium", "low"]


def test_sorted_alerts_same_severity():
    same_severity = [
        Alert(
            "rule1",
            "high",
            "T1110",
            "10.0.0.1",
            datetime(2026, 10, 9, 10, 5, tzinfo=timezone.utc),
            "Later",
        ),
        Alert(
            "rule2",
            "high",
            "T1110",
            "10.0.0.2",
            datetime(2026, 10, 9, 10, 1, tzinfo=timezone.utc),
            "Earlier",
        ),
    ]

    result = engine.sort_alerts(same_severity)

    assert result[0].detail == "Earlier"
    assert result[1].detail == "Later"


def test_summarize():
    alerts = [
        Alert(
            "ssh_bruteforce",
            "high",
            "T1110",
            "192.168.1.10",
            datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc),
            "SSH brute force",
        ),
        Alert(
            "ssh_bruteforce",
            "high",
            "T1110",
            "192.168.1.10",
            datetime(2026, 10, 9, 10, 1, tzinfo=timezone.utc),
            "SSH brute force",
        ),
        Alert(
            "web_injection_probes",
            "medium",
            "T1190",
            "192.168.1.20",
            datetime(2026, 10, 9, 10, 2, tzinfo=timezone.utc),
            "SQL injection probe",
        ),
        Alert(
            "login_after_failures",
            "critical",
            "T1078",
            "192.168.1.30",
            datetime(2026, 10, 9, 10, 3, tzinfo=timezone.utc),
            "Login after failures",
        ),
    ]

    summary = engine.summarize(alerts)

    assert summary["total"] == 4
    assert summary["by_severity"] == {"high": 2, "medium": 1, "critical": 1}
    assert summary["by_rule"] == {
        "ssh_bruteforce": 2,
        "web_injection_probes": 1,
        "login_after_failures": 1,
    }
    assert summary["top_ips"][0] == ("192.168.1.10", 2)
