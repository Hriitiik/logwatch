import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

random.seed(42)
START = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
OUT = Path(__file__).parent

BROWSERS = [
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) Safari/605.1.15",
]

CLEAN_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/products",
    "/contact",
    "/css/app.css",
    "/js/app.js",
]


def at(seconds):
    return START + timedelta(seconds=seconds)


def auth_line(ts, ok, user, ip, invalid=False):
    verb = "Accepted" if ok else "Failed"
    inv = "invalid user " if invalid else ""
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
    pid, port = random.randint(300, 9999), random.randint(1024, 65535)
    return (
        ts,
        f"{stamp} srv sshd[{pid}]: {verb} password for {inv}{user} from {ip} port {port} ssh2",
    )


def web_line(ts, ip, path, ua, status=200):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(200, 9000)
    return ts, f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def main():
    auth, web = [], []
    users = ["alice", "bob", "carol", "dave", "deploy"]
    noise_ips = [f"198.51.100.{i}" for i in range(20, 40)]

    # unharmful noises
    for _ in range(150):
        auth.append(
            auth_line(
                at(random.randint(0, 3600)),
                True,
                random.choice(users),
                random.choice(noise_ips),
            )
        )

    for _ in range(500):
        web.append(
            web_line(
                at(random.randint(0, 3600)),
                random.choice(noise_ips),
                random.choice(CLEAN_PATHS),
                random.choice(BROWSERS),
            )
        )

    # real user 2 typos then success login
    auth += [
        auth_line(at(300), False, "alice", "192.0.2.50"),
        auth_line(at(310), False, "alice", "192.0.2.50"),
        auth_line(at(320), True, "alice", "192.0.2.50"),
    ]

    # attack 1: ssh_bruteforce and login_after_failures
    for i in range(15):
        auth.append(auth_line(at(600 + i * 2), False, "root", "203.0.113.5"))
    auth.append(auth_line(at(640), True, "root", "203.0.113.5"))

    # attack 2: password_spraying, 7 users, slow(not enough for brute force)
    for i, u in enumerate(
        ["admin", "test", "oracle", "ubuntu", "git", "postgres", "guest"]
    ):
        auth.append(auth_line(at(900 + i * 20), False, u, "198.51.100.7", invalid=True))

    # attack 3: web_injection_probes sqli, xss, traversal
    for i, p in enumerate(
        [
            "/search?q=" + quote("' or 1=1"),
            "/page?name=" + quote("<script>alert(1)</script>"),
            "/download?f=" + quote("../../etc/passwd"),
        ]
    ):
        web.append(web_line(at(1200 + i * 3), "192.0.2.9", p, BROWSERS[1]))

    # attack 4: scanner_user_agents with clean paths so that only this function fires
    for i, p in enumerate(["admin", "/login", "/backup"]):
        web.append(
            web_line(
                at(1500 + 2 * i),
                "192.0.2.10",
                p,
                "sqlmap/1.7#stable (https://sqlmap.org)",
                status=404,
            )
        )

    for name, rows in (("auth.log", auth), ("access.log", web)):
        rows.sort(key=lambda r: r[0])
        (OUT / name).write_text("\n".join(line for _, line in rows) + "\n")
    print(f"wrote {len(auth)} auth lines, {len(web)} web lines")


if __name__ == "__main__":
    main()
