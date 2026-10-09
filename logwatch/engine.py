from collections import Counter

from .parsers import parse_auth_file, parse_web_file
from .rules import RULES

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_events(auth_path=None, web_path=None):
    auth = parse_auth_file(auth_path) if auth_path else []
    web = parse_web_file(web_path) if web_path else []
    return {
        "auth": sorted(auth, key=lambda e: e["ts"]),
        "web": sorted(web, key=lambda e: e["ts"]),
    }


def run_rules(event_by_source):
    alerts = []
    for fn, source in RULES.values():
        alerts.extend(fn(event_by_source[source]))
    return alerts


def sort_alerts(alerts):
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.ts))


def summarize(alerts):
    return {
        "total": len(alerts),
        "by_severity": dict(Counter(a.severity for a in alerts)),
        "by_rule": dict(Counter(a.rule for a in alerts)),
        "top_ips": Counter(a.ip for a in alerts).most_common(5),
    }
