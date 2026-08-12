#!/usr/bin/env python3
"""Bring the persistent production firewall in sync with qeli profile pools.

This deliberately does not execute /root/fw.sh because that script flushes every
table. It updates the persistent source atomically, adds only the missing live INPUT
rules, and saves the live ruleset for iptables-persistent. Credentials stay in env.
"""

import datetime
import os
import socket
import sys

import paramiko

import ssh_hostkey


PROD_HOST = os.environ.get("QELI_PROD_HOST", "").strip()
PROD_PASS = os.environ.get("QELI_PROD_PASS", "")
FW_PATH = "/root/fw.sh"
OLD_LOOP = b"for n in 1 2 3 4 5 6; do"
MARKER = b"# qeli managed DNS INPUT for profile pools 7-9"
DNS_BLOCK = b"""# qeli managed DNS INPUT for profile pools 7-9
for n in 7 8 9; do
  iptables -A INPUT -i "vpn${n}" -s "10.9.${n}.0/24" -d "10.9.${n}.1" -p udp --dport 53 -j ACCEPT
  iptables -A INPUT -i "vpn${n}" -s "10.9.${n}.0/24" -d "10.9.${n}.1" -p tcp --dport 53 -j ACCEPT
done
"""
DNS_PROFILES = (7, 8, 9)


def connect() -> paramiko.SSHClient:
    if not PROD_HOST or not PROD_PASS:
        raise SystemExit("QELI_PROD_HOST and QELI_PROD_PASS are required")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.connect((PROD_HOST, 22))
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client)
    client.connect(
        PROD_HOST,
        port=22,
        username="root",
        password=PROD_PASS,
        sock=sock,
        timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(client: paramiko.SSHClient, command: str) -> tuple[int, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=60)
    output = stdout.read().decode("utf-8", "replace")
    output += stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), output.strip()


def main() -> int:
    client = connect()
    sftp = client.open_sftp()
    with sftp.open(FW_PATH, "rb") as source:
        original = source.read()

    if original.count(MARKER) == 1:
        updated = original
    else:
        if original.count(OLD_LOOP) != 1:
            raise SystemExit("unexpected /root/fw.sh subnet loop; refusing to edit")
        loop_start = original.index(OLD_LOOP)
        loop_end = original.find(b"\ndone", loop_start)
        if loop_end < 0:
            raise SystemExit("could not locate the end of the existing pool loop")
        insert_at = original.find(b"\n", loop_end + 1)
        if insert_at < 0:
            insert_at = len(original)
        else:
            insert_at += 1
        updated = original[:insert_at] + DNS_BLOCK + original[insert_at:]

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    backup_dir = "/root/backup/qeli-fw"
    backup = f"{backup_dir}/{stamp}-fw.sh"
    rc, output = run(
        client,
        f"mkdir -p {backup_dir} && cp --preserve=all {FW_PATH} {backup}",
    )
    if rc != 0:
        raise SystemExit(f"firewall backup failed: {output}")

    if updated != original:
        temp_path = f"{FW_PATH}.qeli-new"
        with sftp.open(temp_path, "wb") as target:
            target.write(updated)
        sftp.chmod(temp_path, 0o755)
        rc, output = run(
            client,
            f"bash -n {temp_path} && chown root:root {temp_path} && mv -f {temp_path} {FW_PATH}",
        )
        if rc != 0:
            run(client, f"rm -f {temp_path}")
            raise SystemExit(f"atomic firewall update failed: {output}")

    for number in DNS_PROFILES:
        tun = f"vpn{number}"
        pool = f"10.9.{number}.0/24"
        resolver = f"10.9.{number}.1"
        for proto in ("udp", "tcp"):
            rule = (
                f"-i {tun} -s {pool} -d {resolver} -p {proto} --dport 53 -j ACCEPT"
            )
            rc, output = run(
                client,
                f"iptables -C INPUT {rule} 2>/dev/null || iptables -I INPUT 1 {rule}",
            )
            if rc != 0:
                raise SystemExit(
                    f"live INPUT update failed for {tun} {proto}/53: {output}"
                )

    rc, output = run(client, "iptables-save > /etc/iptables/rules.v4")
    if rc != 0:
        raise SystemExit(f"could not persist live rules: {output}")

    checks = [
        f"grep -Fqx '{MARKER.decode()}' {FW_PATH}",
        f"bash -n {FW_PATH}",
        f"test \"$(stat -c '%a:%U:%G' {FW_PATH})\" = '755:root:root'",
    ]
    for number in DNS_PROFILES:
        tun = f"vpn{number}"
        pool = f"10.9.{number}.0/24"
        resolver = f"10.9.{number}.1"
        for proto in ("udp", "tcp"):
            rule = (
                f"-i {tun} -s {pool} -d {resolver} -p {proto} --dport 53 -j ACCEPT"
            )
            checks.append(f"iptables -C INPUT {rule}")
    rc, output = run(client, " && ".join(checks))
    if rc != 0:
        raise SystemExit(f"firewall verification failed: {output}")

    print("FIREWALL_RESULT: PASS")
    print(f"persistent source: {FW_PATH}")
    print(f"backup: {backup}")
    print("live DNS-only profiles: vpn7, vpn8, vpn9 (udp+tcp/53)")
    sftp.close()
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
