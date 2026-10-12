import argparse
from pathlib import Path

from .engine import load_events, run_rules, sort_alerts, summarize
from .report import alerts_to_json, render_html

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def build_parser():
    p = argparse.ArgumentParser(
        prog="logwatch", description="Mini log detection engine"
    )
    p.add_argument("--auth", help="path to SSH auth.log")
    p.add_argument("--web", help="path to nginx/Apache access log")
    p.add_argument("--out", default="report.html")
    p.add_argument("--json", dest="json_out", default="report.json")
    p.add_argument("--demo", action="store_true", help="use bundled sample logs")
    p.add_argument(
        "--fail-on",
        choices=list(SEVERITY_RANK),
        help="exit 1 if any alert >= this severity",
    )
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.demo:
        args.auth = str(SAMPLES / "auth.log")
        args.web = str(SAMPLES / "access.log")
    if not args.auth and not args.web:
        print("error: provide --auth and/or --web or use --demo")
        return 2

    events = load_events(args.auth, args.web)
    alerts = sort_alerts(run_rules(events))
    summary = summarize(alerts)

    print(
        f"logwatch: parsed {len(events['auth'])} auth events, {len(events['web'])} web events"
    )
    sev = summary["by_severity"]
    print(
        f"ALERTS: {summary['total']} (critical: {sev.get('critical', 0)} | high: {sev.get('high', 0)} | medium: {sev.get('medium', 0)} | low: {sev.get('low', 0)})\n"
    )
    for a in alerts:
        print(f"{a.severity.upper():<9} {a.attack_id:<20} {a.ip:<15} {a.detail}")
    alerts_to_json(alerts, args.json_out)
    render_html(alerts, summary, args.out)
    print(f"\nWrote {args.out}, {args.json_out}")

    if args.fail_on and any(
        SEVERITY_RANK[a.severity] >= SEVERITY_RANK[args.fail_on] for a in alerts
    ):
        return 1
    return 0
