#!/usr/bin/env python3
"""Re-issue current ignored user01 qeli:// links from production without printing secrets.

If the encrypted password copy cannot be recovered, ``QELI_ALLOW_USER01_RESET=1`` permits
the CLI's explicit reset path. The users file is backed up first and the service is restarted
only when a reset actually occurred.
"""

import os
import re
import shlex
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import paramiko

import ssh_hostkey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "release/prod-client-configs/allmodes"
HOST = os.environ.get("QELI_PROD_HOST", "").strip()
PASSWORD = os.environ.get("QELI_PROD_PASS", "")
CONFIG = "/etc/qeli/server-maxobf.conf"
QELI = "/usr/local/bin/qeli"
USER = "user01"
PROFILES = (
    "reality-tls",
    "reality",
    "fake-tls",
    "obfs-ws",
    "obfs-none",
    "plain",
    "udp-fake-tls",
    "udp-quic",
    "udp-obfs",
)


def command(client: paramiko.SSHClient, value: str, check: bool = True) -> tuple[int, str]:
    _, stdout, stderr = client.exec_command(value, timeout=90)
    text = (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).strip()
    status = stdout.channel.recv_exit_status()
    if check and status != 0:
        raise RuntimeError(f"remote command failed ({status}): {text}")
    return status, text


def issue(client: paramiko.SSHClient, profile: str, reset: bool = False) -> tuple[str, bool]:
    args = [
        QELI,
        "share-link",
        USER,
        "--host",
        HOST,
        "--profile",
        profile,
        "--config",
        CONFIG,
    ]
    if reset:
        args.append("--reset")
    status, output = command(client, " ".join(shlex.quote(item) for item in args), check=False)
    links = []
    for candidate in re.findall(r"qeli://[^\s]+", output):
        parsed = urlsplit(candidate)
        if parsed.username and parsed.password is not None and parsed.hostname:
            links.append(candidate)
    if status != 0 or not links:
        raise RuntimeError(output or f"share-link failed for {profile}")
    return links[-1], "Password RESET" in output


def users_file(client: paramiko.SSHClient) -> str:
    _, config = command(client, f"sed -n '1,160p' {CONFIG}")
    match = re.search(r"(?m)^\s*users_file\s*=\s*([^;#\r\n]+)", config)
    if not match:
        raise RuntimeError("auth.users_file was not found in the production config")
    path = match.group(1).strip().strip('"\'')
    if not path.startswith("/etc/qeli/"):
        raise RuntimeError(f"refusing to back up unexpected users file: {path}")
    return path


def main() -> int:
    if not HOST or not PASSWORD:
        raise SystemExit("QELI_PROD_HOST and QELI_PROD_PASS are required")
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client, HOST)
    client.connect(
        HOST,
        username="root",
        password=PASSWORD,
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        reset_happened = False
        try:
            first, _ = issue(client, PROFILES[0])
        except RuntimeError as error:
            if "no recoverable password" not in str(error):
                raise
            if os.environ.get("QELI_ALLOW_USER01_RESET") != "1":
                raise RuntimeError(
                    "user01 password cannot be recovered; set QELI_ALLOW_USER01_RESET=1 "
                    "only with explicit authorisation"
                ) from error
            source = users_file(client)
            backup = f"/root/backup/qeli-user01-e2e/{int(time.time())}/users.conf.bak"
            command(
                client,
                f"mkdir -p {shlex.quote(str(Path(backup).parent))} && "
                f"cp --preserve=all {shlex.quote(source)} {shlex.quote(backup)}",
            )
            first, reset_happened = issue(client, PROFILES[0], reset=True)
            if not reset_happened:
                raise RuntimeError("reset was requested but qeli did not report a password reset")
            command(client, "systemctl restart qeli.service")
            for _ in range(20):
                time.sleep(1)
                _, state = command(
                    client,
                    "systemctl is-active qeli.service; ss -tlnH '( sport = :443 )' | grep -c LISTEN",
                    check=False,
                )
                if state.splitlines() == ["active", "1"]:
                    break
            else:
                raise RuntimeError("qeli.service did not recover after the authorised user01 reset")
            print(f"user01 password reset; backup={backup}")

        links = {PROFILES[0]: first}
        for profile in PROFILES[1:]:
            links[profile], unexpected_reset = issue(client, profile)
            if unexpected_reset:
                raise RuntimeError(f"unexpected second reset while issuing {profile}")

        # Validate that every link carries one consistent credential before replacing the
        # ignored test set. Passwords and full URIs are intentionally never printed.
        passwords = set()
        for profile, link in links.items():
            parsed = urlsplit(link)
            if parsed.username != USER or parsed.hostname != HOST or parsed.password is None:
                raise RuntimeError(
                    f"malformed production link for {profile}: "
                    f"scheme_ok={parsed.scheme == 'qeli'} "
                    f"user_ok={parsed.username == USER} "
                    f"host_ok={parsed.hostname == HOST} "
                    f"password_present={parsed.password is not None} port={parsed.port}"
                )
            passwords.add(parsed.password)
        if len(passwords) != 1:
            raise RuntimeError("share-link returned inconsistent user01 passwords")

        OUTPUT.mkdir(parents=True, exist_ok=True)
        for profile, link in links.items():
            target = OUTPUT / f"{USER}__{profile}.qeli"
            target.write_text(link + "\n", encoding="utf-8")
            parsed = urlsplit(link)
            query = parse_qs(parsed.query)
            print(
                f"issued {profile}: {query.get('proto', ['?'])[0]}:{parsed.port} "
                f"mode={query.get('mode', ['?'])[0]}"
            )
        print("PROD_LINKS_RESULT: PASS" + (" (password reset)" if reset_happened else " (re-issued)"))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PROD_LINKS_RESULT: FAIL ({error})", file=sys.stderr)
        raise SystemExit(1)
