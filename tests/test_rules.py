from datetime import datetime, timedelta, timezone

from logwatch import rules

T0 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def fail(ip, secs, user="admin", event="failed_login"):
    return {"ts": T0 + timedelta(seconds=secs), "event": event, "ip": ip, "user": user}


def test_ssh_bruteforce_detected():

    events = [fail("192.168.1.10", i) for i in range(10)]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "ssh_bruteforce"
    assert alerts[0].severity == "high"
    assert alerts[0].ip == "192.168.1.10"


def test_ssh_bruteforce_multiple_detected():

    events = [fail("192.168.1.10", i) for i in range(10)]
    events += [fail("192.168.1.20", i) for i in range(10)]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 2
    assert alerts[0].rule == "ssh_bruteforce"
    assert alerts[0].severity == "high"
    assert alerts[0].ip == "192.168.1.10"
    assert alerts[1].rule == "ssh_bruteforce"
    assert alerts[1].severity == "high"
    assert alerts[1].ip == "192.168.1.20"


def test_ssh_bruteforce_below_threshold():

    events = [fail("1.1.1.1", i) for i in range(9)]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 0


def test_ssh_bruteforce_outside_window():

    events = [fail("1.1.1.1", i * 7) for i in range(10)]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 0


def test_ssh_bruteforce_not_same_user():

    events = [
        fail("1.1.1.1", i, user="user" + str(i)) for i in range(10) for i in range(10)
    ]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 1


def test_ssh_bruteforce_once_per_ip():

    events = [fail("1.1.1.1", i) for i in range(20)]

    alerts = rules.ssh_bruteforce(events)

    assert len(alerts) == 1


def test_password_spraying_detected():

    events = [
        fail("1.1.1.1", i, user="user" + str(i)) for i in range(10) for i in range(10)
    ]

    alerts = rules.password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "password_spraying"
    assert alerts[0].severity == "high"
    assert alerts[0].ip == "1.1.1.1"


def test_password_spraying_same_user_not_detected():

    events = [fail("1.1.1.1", i) for i in range(10)]

    alerts = rules.password_spraying(events)

    assert len(alerts) == 0


def test_login_after_failures():
    events = [fail("1.1.1.1", i) for i in range(5)]
    events += [fail("1.1.1.1", secs=59, event="successful_login")]
    alerts = rules.login_after_failures(events)
    assert len(alerts) == 1


def test_login_after_failures_not_detected():
    events = [fail("1.1.1.1", i) for i in range(4)]
    events += [fail("1.1.1.1", secs=59, event="successful_login")]
    alerts = rules.login_after_failures(events)
    assert len(alerts) == 0


def test_web_injection_prob_sqli():
    events = [
        {
            "ts": datetime(2026, 10, 8, 10, 15, 1, tzinfo=timezone.utc),
            "source": "web",
            "ip": "192.168.1.50",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/products?id=1' OR 1=1--",
            "ua": "Mozilla/5.0",
        }
    ]
    alerts = rules.web_injection_probes(events)
    assert alerts[0].detail == "Detected possible SQL Injection Pattern in url"


def test_web_injection_prob_xss():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 16, 22, tzinfo=timezone.utc),
            "source": "web",
            "ip": "192.168.1.51",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/search?q=<script>alert(1)</script>",
            "ua": "Mozilla/5.0",
        }
    ]
    alerts = rules.web_injection_probes(event)
    assert alerts[0].detail == "Detected possible XSS Pattern in url"


def test_web_injection_prob_path_traversal():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 17, 43, tzinfo=timezone.utc),
            "source": "web",
            "ip": "192.168.1.52",
            "user": None,
            "event": "web_request",
            "status": 404,
            "path": "/download?file=../../../etc/passwd",
            "ua": "Mozilla/5.0",
        }
    ]
    alerts = rules.web_injection_probes(event)
    assert alerts[0].detail == "Detected possible Path Traversal Pattern in url"


def test_web_injection_prob_command_injection():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 18, 55, tzinfo=timezone.utc),
            "source": "web",
            "ip": "192.168.1.53",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/ping?host=127.0.0.1;whoami",
            "ua": "Mozilla/5.0",
        },
    ]
    alerts = rules.web_injection_probes(event)
    assert alerts[0].detail == "Detected possible Command Injection Pattern in url"


def test_web_injection_prob_normal():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 20, 1, tzinfo=timezone.utc),
            "source": "web",
            "ip": "10.0.0.25",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/products?id=123",
            "ua": "Mozilla/5.0",
        }
    ]
    alerts = rules.web_injection_probes(event)
    assert len(alerts) == 0


def test_scanner_user_agent():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 20, 1, tzinfo=timezone.utc),
            "source": "web",
            "ip": "10.0.0.25",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/products?id=123",
            "ua": "sqlmap/1.8.2",
        }
    ]
    alerts = rules.scanner_user_agents(event)
    assert len(alerts) == 1
    assert alerts[0].rule == "scanner_user_agents"


def test_normal_user_agent():
    event = [
        {
            "ts": datetime(2026, 10, 8, 10, 20, 1, tzinfo=timezone.utc),
            "source": "web",
            "ip": "10.0.0.25",
            "user": None,
            "event": "web_request",
            "status": 200,
            "path": "/products?id=123",
            "ua": "Mozilla/5.0",
        }
    ]
    alerts = rules.scanner_user_agents(event)
    assert len(alerts) == 0
