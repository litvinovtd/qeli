#!/usr/bin/env python3
"""Dual-stack panel E2E for server push, client policy and iroutes.

The test uses the disposable Qeli lab only:

* .10 runs a temporary panel/server with one TCP and one UDP+QUIC profile;
* every profile is changed through ``PUT /api/config``;
* the user IPv6 reservation and ``client_subnets`` are changed through ``PUT /api/users``;
* .11 connects with IPv6 ``include``, ``exclude`` and ``lan_subnet_ipv6``;
* the script verifies the real client/server route tables, DNS plan and traffic to an IPv6
  address behind the client.

It deliberately does not reboot the lab. Run it only after the normal clean-lab reboot and
emulator-off gate used by the benchmark workflow.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import sys
import time

import paramiko

import ssh_hostkey


sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PASSWORD = os.environ.get("QELI_LAB_PASS", "")
if not PASSWORD:
    raise SystemExit("QELI_LAB_PASS is required; source scripts/lab_env.sh first")

SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root", PASSWORD)
CLIENT = (os.environ.get("QELI_LAB_CLIENT", "10.66.116.11"), "root", PASSWORD)
QELI = os.environ.get("QELI_LAB_SRC_BIN", "/opt/qeli-src/target/release/qeli")
CLIENT_BIN = "/usr/local/bin/qeli"
ROOT = "/etc/qeli/panel6e2e"
CONFIG = f"{ROOT}/server.conf"
USERS = f"{ROOT}/users.conf"
PANEL_PORT = 8086
ADMIN_PASSWORD = "PanelIpv6E2E-Only!"
USER = "panel6"
USER_PASSWORD = "testpass123"
PASSWORD_HASH = (
    "$argon2id$v=19$m=16384,t=2,p=1$"
    "cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
)
RESULT_PATH = Path(
    os.environ.get("QELI_PANEL_IPV6_RESULT", "release/panel_ipv6_e2e_current.json")
)

CASES = (
    {
        "name": "tcp",
        "profile": "panel6-tcp",
        "port": 8467,
        "proto": "tcp",
        "tun": "p6t0",
        "dev": "p6tc0",
        "v4": "10.94.0",
        "v6": "fd71:e1:94:1",
        "push": "2001:db8:94::/64",
        "include": "2001:db8:194::/64",
        "client_subnet": "2001:db8:294::/64",
        "static": "fd71:e1:94:1::60",
    },
    {
        "name": "udp-quic",
        "profile": "panel6-udp",
        "port": 8468,
        "proto": "udp",
        "tun": "p6u0",
        "dev": "p6uc0",
        "v4": "10.95.0",
        "v6": "fd71:e1:95:1",
        "push": "2001:db8:95::/64",
        "include": "2001:db8:195::/64",
        "client_subnet": "2001:db8:295::/64",
        "static": "fd71:e1:95:1::60",
    },
)
EXCLUDE = "fd66:116::123/128"


def connect(host: tuple[str, str, str]) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client)
    client.connect(
        host[0],
        username=host[1],
        password=host[2],
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


server = connect(SERVER)
client = connect(CLIENT)


def run(ssh: paramiko.SSHClient, command: str, timeout: int = 60) -> str:
    _, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    return (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).rstrip()


def put(ssh: paramiko.SSHClient, path: str, data: str) -> None:
    sftp = ssh.open_sftp()
    try:
        sftp.putfo(io.BytesIO(data.encode()), path)
    finally:
        sftp.close()


def launch(ssh: paramiko.SSHClient, command: str) -> None:
    channel = ssh.get_transport().open_session()
    channel.exec_command(command)
    time.sleep(1)
    channel.close()


checks: list[dict[str, object]] = []


def check(case: str, name: str, passed: bool, detail: str = "") -> None:
    checks.append({"case": case, "name": name, "passed": passed, "detail": detail})
    print(f"  [{'PASS' if passed else 'FAIL'}] {case}: {name}")
    if detail and not passed:
        print("         ", detail[:500].replace("\n", " | "))


def profile_ini(case: dict[str, object]) -> str:
    quic = "obf.quic.enabled = true\n" if case["proto"] == "udp" else ""
    return f"""
[profile:{case['profile']}]
identity_key = {ROOT}/identity.key
bind.address = 0.0.0.0
bind.port = {case['port']}
bind.transport = {case['proto']}
tun.name = {case['tun']}
tun.ip_mode = dual
tun.address = {case['v4']}.1
tun.ipv6_address = {case['v6']}::1
tun.mtu = 1400
pool.cidr = {case['v4']}.0/24
pool.exclude = {case['v4']}.1
pool.ipv6.cidr = {case['v6']}::/64
routing.ipv6.mode = route
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
{quic}"""


BASE_CONFIG = f"""[auth]
users_file = {USERS}
require_client_key_proof = false

[web]
enabled = true
bind = 127.0.0.1
port = {PANEL_PORT}
username = admin

[logging]
level = info
""" + "".join(profile_ini(case) for case in CASES)

BASE_USERS = f"""[user:{USER}]
password_hash = {PASSWORD_HASH}
enabled = true
"""

JAR = f"{ROOT}/cookies.txt"
BODY = f"{ROOT}/body.json"


def api(method: str, path: str, body: object | None = None) -> dict[str, object]:
    body_args = ""
    if body is not None:
        put(server, BODY, json.dumps(body))
        body_args = f" --data @{BODY}"
    raw = run(
        server,
        f"curl -sS -b {JAR} -X {method} -H 'Content-Type: application/json' "
        f"-H 'Origin: http://127.0.0.1:{PANEL_PORT}'{body_args} "
        f"http://127.0.0.1:{PANEL_PORT}/{path}",
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"panel returned non-JSON for {method} {path}: {raw[:300]}") from error


def wait_for(command: str, needle: str, timeout: int = 20) -> str:
    deadline = time.time() + timeout
    output = ""
    while time.time() < deadline:
        output = run(client, command)
        if needle in output:
            return output
        time.sleep(1)
    return output


def client_config(case: dict[str, object], public_key: str) -> str:
    quic = "quic = true\n" if case["proto"] == "udp" else ""
    return f"""[qeli]
server = {SERVER[0]}:{case['port']}
proto = {case['proto']}
user = {USER}
pass = {USER_PASSWORD}
key = {public_key}
mode = fake-tls
sni = www.microsoft.com
dev = {case['dev']}
ipv6 = required
include = {case['include']}
exclude = {EXCLUDE}
forward = true
lan_subnet_ipv6 = {case['client_subnet']}
dns = tunnel
{quic}
[logging]
level = debug
"""


def clean_case(case: dict[str, object]) -> None:
    behind = str(case["client_subnet"]).split("/", 1)[0] + "7"
    run(client, "pkill -9 -x qeli 2>/dev/null; true")
    time.sleep(1)
    run(client, f"ip link del {case['dev']} 2>/dev/null; true")
    for cidr in (case["push"], case["include"], EXCLUDE):
        run(client, f"ip -6 route del {cidr} 2>/dev/null; true")
    run(client, f"ip -6 addr del {behind}/128 dev lo 2>/dev/null; true")
    run(client, "cp /root/panel6-resolv.bak /etc/resolv.conf 2>/dev/null; true")


def cleanup() -> None:
    for case in CASES:
        clean_case(case)
    run(server, "pkill -9 -f '[p]anel6e2e/server.conf' 2>/dev/null; true")
    for case in CASES:
        run(server, f"ip link del {case['tun']} 2>/dev/null; true")
    run(server, f"rm -rf {ROOT}")


try:
    print("=== prepare temporary dual-stack panel server ===")
    cleanup()
    run(server, f"mkdir -p {ROOT}")
    put(server, CONFIG, BASE_CONFIG)
    put(server, USERS, BASE_USERS)
    password_result = run(
        server,
        f"{QELI} set-web-password --username admin --password '{ADMIN_PASSWORD}' "
        f"--config {CONFIG} 2>&1",
    )
    check("setup", "web password configured", "error" not in password_result.lower(), password_result)

    identities = run(server, f"{QELI} show-identity --config {CONFIG} 2>&1")
    key_match = re.search(r"[0-9a-f]{64}", identities)
    public_key = key_match.group(0) if key_match else ""
    check("setup", "server identity available", bool(public_key), identities)

    launch(
        server,
        f"RUST_LOG=info setsid nohup {QELI} server -c {CONFIG} "
        f">{ROOT}/server.log 2>&1 </dev/null & echo $! >{ROOT}/server.pid",
    )
    panel_up = False
    for _ in range(20):
        if run(server, f"ss -tln | grep -c ':{PANEL_PORT} '").strip() not in ("", "0"):
            panel_up = True
            break
        time.sleep(1)
    check("setup", "panel listener is up", panel_up, run(server, f"tail -20 {ROOT}/server.log"))

    login = run(
        server,
        f"curl -sS -c {JAR} -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"admin\",\"password\":\"{ADMIN_PASSWORD}\"}}' "
        f"http://127.0.0.1:{PANEL_PORT}/api/login",
    )
    check("setup", "panel login", bool(json.loads(login).get("ok")), login)

    config_reply = api("GET", "api/config")
    config = config_reply["config"]
    by_name = {profile["name"]: profile for profile in config["profiles"]}
    for case in CASES:
        profile = by_name[str(case["profile"])]
        profile["routing"]["advertised_routes"] = [
            {"cidr": case["push"], "gateway": None, "metric": 77}
        ]
        profile["dns"]["push_servers"] = [f"{case['v6']}::1"]
    saved = api(
        "PUT",
        "api/config",
        {"config": config, "expected_revision": config_reply.get("revision")},
    )
    check("setup", "dual-stack push settings saved through panel", bool(saved.get("ok")), str(saved))

    written = run(
        server,
        f"grep -E '^(tun.ip_mode|tun.ipv6_address|pool.ipv6.cidr|route|dns.push_servers)' {CONFIG}",
    )
    for case in CASES:
        check(
            "setup",
            f"{case['profile']} IPv6 push reached flat INI",
            str(case["push"]) in written and f"{case['v6']}::1" in written,
            written,
        )

    sftp = server.open_sftp()
    binary = io.BytesIO()
    sftp.getfo(QELI, binary)
    sftp.close()
    binary.seek(0)
    sftp = client.open_sftp()
    sftp.putfo(binary, CLIENT_BIN)
    sftp.close()
    run(client, f"chmod 755 {CLIENT_BIN}; mkdir -p /etc/qeli")
    run(client, "cp /etc/resolv.conf /root/panel6-resolv.bak 2>/dev/null; true")

    for case in CASES:
        print(f"\n=== {case['name']} IPv6 panel contract ===")
        clean_case(case)
        behind = str(case["client_subnet"]).split("/", 1)[0] + "7"
        user_saved = api(
            "PUT",
            f"api/users/{USER}",
            {
                "static_ipv6": case["static"],
                "profiles": [case["profile"]],
                "client_subnets": [case["client_subnet"]],
            },
        )
        check(case["name"], "static IPv6 and client_subnet saved through users panel", bool(user_saved.get("ok")), str(user_saved))

        put(client, f"/etc/qeli/{case['name']}.conf", client_config(case, public_key))
        run(client, f"ip -6 addr add {behind}/128 dev lo")
        launch(
            client,
            f"RUST_LOG=debug setsid nohup {CLIENT_BIN} client "
            f"-c /etc/qeli/{case['name']}.conf >/tmp/{case['name']}.log 2>&1 </dev/null &",
        )
        log = wait_for(f"cat /tmp/{case['name']}.log 2>/dev/null", "Auth OK", 25)
        check(case["name"], "client authenticated", "Auth OK" in log, log[-1000:])
        time.sleep(2)

        address = run(client, f"ip -6 -br addr show dev {case['dev']} 2>/dev/null")
        check(case["name"], "panel static_ipv6 assigned", str(case["static"]) in address, address)

        pushed = run(client, f"ip -6 route show exact {case['push']}")
        included = run(client, f"ip -6 route show exact {case['include']}")
        excluded = run(client, f"ip -6 route show exact {EXCLUDE}")
        check(case["name"], "IPv6 pushed route uses the tunnel", str(case["dev"]) in pushed, pushed)
        check(case["name"], "IPv6 include uses the tunnel", str(case["dev"]) in included, included)
        check(
            case["name"],
            "IPv6 exclude stays on the physical path",
            bool(excluded) and str(case["dev"]) not in excluded,
            excluded,
        )

        dns_state = run(
            client,
            f"(resolvectl dns {case['dev']} 2>/dev/null || cat /etc/resolv.conf 2>/dev/null)",
        )
        check(case["name"], "IPv6 DNS push reached the client", f"{case['v6']}::1" in dns_state, dns_state)

        iroute = run(server, f"ip -6 route show table main exact {case['client_subnet']}")
        check(
            case["name"],
            "IPv6 client_subnet kernel iroute uses the profile TUN",
            str(case["tun"]) in iroute and "metric 42760" in iroute,
            iroute,
        )
        ping = run(server, f"ping -6 -c 3 -W 1 {behind}", timeout=10)
        check(case["name"], "traffic reaches IPv6 LAN behind the client", "0% packet loss" in ping, ping)

        clean_case(case)
        time.sleep(2)
        stale = run(server, f"ip -6 route show table main exact {case['client_subnet']}")
        check(case["name"], "client_subnet route is removed on disconnect", not stale.strip(), stale)

finally:
    cleanup()
    server.close()
    client.close()

passed = sum(1 for item in checks if item["passed"])
failed = len(checks) - passed
result = {
    "meta": {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "server": SERVER[0],
        "client": CLIENT[0],
        "binary": QELI,
        "passed": passed,
        "failed": failed,
    },
    "checks": checks,
}
RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
RESULT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"\nRESULT: {passed}/{len(checks)} passed; report: {RESULT_PATH}")
raise SystemExit(1 if failed else 0)
