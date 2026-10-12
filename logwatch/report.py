import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SEVERITIES = ["critical", "high", "medium", "low"]


def alerts_to_json(alerts, path):
    data = [
        {
            "rule": a.rule,
            "severity": a.severity,
            "attack_id": a.attack_id,
            "ip": a.ip,
            "ts": a.ts.isoformat(),
            "detail": a.detail,
        }
        for a in alerts
    ]
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def render_html(alerts, summary, out_path):
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    html = env.get_template("report.html.j2").render(
        alerts=alerts, summary=summary, severities=SEVERITIES
    )
    Path(out_path).write_text(html, encoding="utf-8")
