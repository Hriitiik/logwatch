import re
from datetime import datetime, timezone

AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<kind>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)


def parse_auth_line(line, year):
    m = AUTH_RE.match(line)
    if not m:
        return None
    ts = datetime.strptime(
        f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)
    return {
        "ts": ts,
        "source": "auth",
        "ip": m["ip"],
        "user": m["user"],
        "event": "failed_login" if m["kind"] == "Failed" else "successful_login",
        "status": None,
        "path": None,
        "ua": None,
    }


def parse_auth_file(path, year=None):
    year = year or datetime.now(timezone.utc).year
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_auth_line(line.rstrip("\n"), year)
            if e:
                events.append(e)
    return events
