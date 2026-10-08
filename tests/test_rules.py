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
    start = datetime(2026, 10, 4, 12, 0, 0)

    events = [
        {
            "event": "failed_login",
            "ip": "192.168.1.10",
            "user": "user" + str(i),
            "ts": start + timedelta(seconds=i),
        }
        for i in range(10)
    ]

    alerts = rules.password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "password_spraying"
    assert alerts[0].severity == "high"
    assert alerts[0].ip == "192.168.1.10"


def test_password_spraying_same_user_not_detected():
    start = datetime(2026, 10, 4, 12, 0, 0)

    events = [
        {
            "event": "failed_login",
            "ip": "192.168.1.10",
            "user": "user",
            "ts": start + timedelta(seconds=i),
        }
        for i in range(10)
    ]

    alerts = rules.password_spraying(events)

    assert len(alerts) == 0
