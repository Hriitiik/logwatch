import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    rule: str
    severity: str
    attack_id: str
    ip: str
    ts: datetime
    detail: str


def ssh_bruteforce(events, threshold=10, window=60):

    alerts = []

    # failed ssh logins

    failed = [event for event in events if event["event"] == "failed_login"]

    # group by ip

    by_ip = {}

    for event in failed:
        ip = event["ip"]

        by_ip.setdefault(ip, []).append(event)

    # check ips

    for ip, ip_events in by_ip.items():
        # chronological sorting of events

        ip_events.sort(key=lambda event: event["ts"])

        for i in range(len(ip_events)):
            start_time = ip_events[i]["ts"]

            count = 0

            # count failures within the window

            for j in range(i, len(ip_events)):
                current_time = ip_events[j]["ts"]

                if (current_time - start_time).total_seconds() <= window:
                    count += 1

                else:
                    break

            # threshold reached

            if count >= threshold:
                alerts.append(
                    Alert(
                        rule="ssh_bruteforce",
                        severity="high",
                        attack_id="T1110.001",
                        ip=ip,
                        ts=ip_events[i]["ts"],
                        detail=f"{count} failed SSH logins within {window} seconds",
                    )
                )

                break

    return alerts


def password_spraying(events, threshold=7, window=60):
    alerts = []

    # failed ssh logins
    failed = [event for event in events if event["event"] == "failed_login"]

    # group by ip
    by_ip = {}

    for event in failed:
        ip = event["ip"]
        by_ip.setdefault(ip, []).append(event)

    # check ips
    for ip, ip_events in by_ip.items():
        # chronological sorting of events
        ip_events.sort(key=lambda event: event["ts"])

        for i in range(len(ip_events)):
            start_time = ip_events[i]["ts"]
            usernames = set()

            # count failures within the window
            for j in range(i, len(ip_events)):
                current_time = ip_events[j]["ts"]
                if (current_time - start_time).total_seconds() <= window:
                    if ip_events[j]["user"] not in usernames:
                        usernames.add(ip_events[j]["user"])
                else:
                    break

            # threshold reached
            if len(usernames) >= threshold:
                alerts.append(
                    Alert(
                        rule="password_spraying",
                        severity="high",
                        attack_id="T1110.003",
                        ip=ip,
                        ts=ip_events[i]["ts"],
                        detail=f"{len(usernames)} different usernames failed logins within {window} seconds",
                    )
                )
                break
    return alerts


def login_after_failures(events, min_failures=5, window=60):

    alerts = []

    by_ip = {}

    # group by ip
    for event in events:
        ip = event["ip"]
        by_ip.setdefault(ip, []).append(event)

    # check each ip
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda event: event["ts"])

        for i, e in enumerate(ip_events):
            if e["event"] != "successful_login":
                continue

            end_time = e["ts"]
            count = 0

            # look only at events before this successful login
            for previous in reversed(ip_events[:i]):
                # outside the window
                if (end_time - previous["ts"]).total_seconds() > window:
                    break

                if previous["event"] == "failed_login":
                    count += 1

            # threshold reached
            if count >= min_failures:
                alerts.append(
                    Alert(
                        rule="login_after_failures",
                        severity="critical",
                        attack_id="T1078",
                        ip=ip,
                        ts=e["ts"],
                        detail=f"{count} failed logins before successful login from ip: {ip}",
                    )
                )

    return alerts


# info for auth reference
# "ts": ts,
# "source": "auth",
# "ip": m["ip"],
# "user": m["user"],
# "event": "failed_login" if m["kind"] == "Failed" else "successful_login",
# "status": None,
# "path": None,
# "ua": None

# possible patterns for web injection
SQL_PATTERNS = [
    r"'\s*(or|and)\s+",
    r"\bunion\s+select\b",
    r"\bselect\b.+\bfrom\b",
    r"--",
    r"/\*",
]

XSS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<svg",
    r"<img",
    r"alert\s*\(",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
]

COMMAND_PATTERNS = [
    r";\s*(whoami|id|cat|curl|wget|nc)\b",
    r"\$\(",
    r"`[^`]+`",
]


def web_injection_probes(events):
    alerts = []
    for event in events:
        path = event["path"]
        # searching for different possible patterns in path
        if any(re.search(pattern, path, re.IGNORECASE) for pattern in SQL_PATTERNS):
            alerts.append(
                Alert(
                    rule="web_injection_probes",
                    severity="medium",
                    attack_id="T1595.002",
                    ip=event["ip"],
                    ts=event["ts"],
                    detail="Detected possible SQL Injection Pattern in url",
                )
            )

        elif any(re.search(pattern, path, re.IGNORECASE) for pattern in XSS_PATTERNS):
            alerts.append(
                Alert(
                    rule="web_injection_probes",
                    severity="medium",
                    attack_id="T1595.002",
                    ip=event["ip"],
                    ts=event["ts"],
                    detail="Detected possible XSS Pattern in url",
                )
            )
        elif any(
            re.search(pattern, path, re.IGNORECASE) for pattern in TRAVERSAL_PATTERNS
        ):
            alerts.append(
                Alert(
                    rule="web_injection_probes",
                    severity="medium",
                    attack_id="T1595.002",
                    ip=event["ip"],
                    ts=event["ts"],
                    detail="Detected possible Path Traversal Pattern in url",
                )
            )
        elif any(
            re.search(pattern, path, re.IGNORECASE) for pattern in COMMAND_PATTERNS
        ):
            alerts.append(
                Alert(
                    rule="web_injection_probes",
                    severity="medium",
                    attack_id="T1595.002",
                    ip=event["ip"],
                    ts=event["ts"],
                    detail="Detected possible Command Injection Pattern in url",
                )
            )
    return alerts


SCANNER_SIGNATURES = [
    "sqlmap",
    "nikto",
    "nmap",
    "nuclei",
    "dirsearch",
    "gobuster",
    "ffuf",
    "zgrab",
    "wfuzz",
]


def scanner_user_agents(events):
    alerts = []
    for event in events:
        ua = event["ua"] or ""
        if any(signature in ua.lower() for signature in SCANNER_SIGNATURES):
            alerts.append(
                Alert(
                    rule="scanner_user_agents",
                    severity="low",
                    attack_id="T1595",
                    ip=event["ip"],
                    ts=event["ts"],
                    detail=f"Possible scanner detected in user-agent: {ua}",
                )
            )
    return alerts


# info for web references
# "ts": ts,
# "source": "web",
# "ip": m["ip"],
# "user": None,
# "event": "web_request",
# "status": int(m["status"]),
# "path": unquote_plus(m["path"]),
# "ua": m["ua"],
