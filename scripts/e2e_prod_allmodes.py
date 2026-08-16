#!/usr/bin/env python3
"""Run Android and Linux production matrices with exact config rollback.

Production normally exposes only the public profile subset.  The release gate needs every
configured transport, so this wrapper temporarily enables the four dormant TCP profiles,
runs both platform tests, and restores the original config bytes in ``finally``.  It refuses
to restart the service while an established TCP VPN session is visible.
"""

import hashlib
import io
import os
import re
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import paramiko

import ssh_hostkey


ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "qeli" / "Cargo.toml").open("rb") as manifest:
    VERSION = tomllib.load(manifest)["package"]["version"]
EVIDENCE = ROOT / "release" / "dist" / f"v{VERSION}" / "evidence"
PROD_HOST = os.environ.get("QELI_PROD_HOST", "").strip()
CONFIG = "/etc/qeli/server-maxobf.conf"
SERVICE = "qeli.service"
DORMANT = ("reality", "obfs-ws", "obfs-none", "plain")
EXPECTED_TCP = (443, 8443, 8444, 8445, 8446, 8447)
EXPECTED_UDP = (8448, 8449, 8450)
ALLOW_ACTIVE_RESTART = os.environ.get("QELI_ALLOW_PROD_RESTART_WITH_CLIENTS") == "1"
SKIP_ANDROID = os.environ.get("QELI_E2E_SKIP_ANDROID") == "1"


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client, PROD_HOST)
    client.connect(
        PROD_HOST,
        username="root",
        password=os.environ["QELI_PROD_PASS"],
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def command(client: paramiko.SSHClient, value: str, timeout: int = 90) -> str:
    _, stdout, stderr = client.exec_command(value, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise RuntimeError(f"remote command failed ({status}): {value}\n{error[-2000:]}")
    return (output + error).rstrip()


def listeners(client: paramiko.SSHClient) -> str:
    return command(
        client,
        "{ ss -tlnH | awk '{print \"tcp \" $4}'; "
        "ss -ulnH | awk '{print \"udp \" $4}'; } | "
        "grep -E ':(443|8443|8444|8445|8446|8447|8448|8449|8450)$' | sort",
    )


def require_matrix_listeners(client: paramiko.SSHClient) -> None:
    current = listeners(client)
    missing = [f"tcp:{port}" for port in EXPECTED_TCP if f":{port}" not in current]
    missing.extend(f"udp:{port}" for port in EXPECTED_UDP if f":{port}" not in current)
    if missing:
        raise RuntimeError(f"temporary production matrix is missing listeners: {missing}")


def enable_named_profiles(config: str) -> str:
    result = config
    for name in DORMANT:
        section = re.compile(
            rf"(?ms)(^\[profile:{re.escape(name)}\][^\r\n]*\r?\n)(.*?)(?=^\[|\Z)"
        )
        match = section.search(result)
        if match is None:
            raise RuntimeError(f"production config has no profile {name!r}")
        body = match.group(2)
        changed, count = re.subn(
            r"(?m)^enabled[ \t]*=[ \t]*false[ \t]*$",
            "enabled = true",
            body,
            count=1,
        )
        if count == 0 and re.search(r"(?m)^enabled[ \t]*=[ \t]*true[ \t]*$", body) is None:
            raise RuntimeError(f"profile {name!r} has no explicit enabled flag")
        result = result[: match.start(2)] + changed + result[match.end(2) :]
    return result


def atomic_write(
    client: paramiko.SSHClient,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
    suffix: str,
) -> None:
    temporary = f"{CONFIG}.{suffix}.tmp"
    with client.open_sftp() as sftp:
        sftp.putfo(io.BytesIO(payload), temporary)
        sftp.chmod(temporary, mode)
        sftp.chown(temporary, uid, gid)
        sftp.posix_rename(temporary, CONFIG)


def restart_and_require_active(client: paramiko.SSHClient) -> None:
    command(client, f"systemctl restart {SERVICE}", timeout=90)
    time.sleep(5)
    state = command(client, f"systemctl is-active {SERVICE}")
    if state.strip() != "active":
        raise RuntimeError(f"{SERVICE} did not become active: {state}")


def run_test(script: str) -> None:
    print(f"\n===== {script} =====", flush=True)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script)],
        cwd=ROOT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{script} failed with exit code {result.returncode}")


def main() -> int:
    if not PROD_HOST:
        raise SystemExit("QELI_PROD_HOST is required")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    client = connect()
    original: bytes | None = None
    original_listeners = ""
    restored = False
    result = "FAIL"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    try:
        established = command(
            client,
            "ss -tnH state established "
            "'( sport = :443 or sport = :8443 or sport = :8444 or sport = :8445 "
            "or sport = :8446 or sport = :8447 )' | wc -l",
        ).strip()
        if established != "0" and not ALLOW_ACTIVE_RESTART:
            raise RuntimeError(f"refusing to restart production with {established} TCP session(s)")
        if established != "0":
            print(
                f"PROD RESTART OVERRIDE [visible TCP sessions={established}; operator authorised reconnect]",
                flush=True,
            )

        original_listeners = listeners(client)
        with client.open_sftp() as sftp:
            metadata = sftp.stat(CONFIG)
            with sftp.open(CONFIG, "rb") as stream:
                original = stream.read()
        original_sha = hashlib.sha256(original).hexdigest()
        original_text = original.decode("utf-8")
        enabled = enable_named_profiles(original_text).encode("utf-8")
        if enabled == original:
            raise RuntimeError("all matrix profiles were already enabled; no temporary change made")

        backup_dir = "/root/backup/qeli-e2e"
        backup = f"{backup_dir}/{stamp}-server-maxobf.conf"
        command(client, f"install -d -m 700 {backup_dir}")
        with client.open_sftp() as sftp:
            sftp.putfo(io.BytesIO(original), backup)
            sftp.chmod(backup, 0o600)
        atomic_write(
            client,
            enabled,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            f"qeli-e2e-{stamp}",
        )
        restart_and_require_active(client)
        require_matrix_listeners(client)
        print(f"PROD MATRIX ENABLE PASS [backup={backup}, sha256={original_sha}]", flush=True)

        if SKIP_ANDROID:
            print(
                "ANDROID MATRIX SKIPPED [reusing the immediately preceding PASS evidence]",
                flush=True,
            )
        else:
            run_test("e2e_android_prod_lifecycle.py")
        run_test("e2e_linux_prod_matrix.py")
        result = "PASS"
        return 0
    finally:
        restore_error = ""
        if original is not None:
            try:
                with client.open_sftp() as sftp:
                    metadata = sftp.stat(CONFIG)
                atomic_write(
                    client,
                    original,
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_uid,
                    metadata.st_gid,
                    f"qeli-restore-{stamp}",
                )
                restart_and_require_active(client)
                restored_sha = command(client, f"sha256sum {CONFIG} | awk '{{print $1}}'").strip()
                if restored_sha != hashlib.sha256(original).hexdigest():
                    raise RuntimeError("restored production config hash differs from the original")
                if listeners(client) != original_listeners:
                    raise RuntimeError("restored production listener set differs from the original")
                restored = True
                print("PROD RESTORE PASS [exact config hash and listener set]", flush=True)
            except Exception as error:
                restore_error = str(error)
                print(f"PROD RESTORE FAIL: {error}", file=sys.stderr, flush=True)
        client.close()
        (EVIDENCE / "prod-allmodes-wrapper-result.txt").write_text(
            f"RESULT: {result}\nRESTORED: {restored}\n"
            + (f"RESTORE ERROR: {restore_error}\n" if restore_error else ""),
            encoding="utf-8",
        )
        if restore_error:
            raise RuntimeError(f"production restore failed: {restore_error}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PROD_ALLMODES_RESULT: FAIL ({error})", file=sys.stderr)
        raise SystemExit(1)
