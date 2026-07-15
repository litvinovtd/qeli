"""Shared SSH / lab helpers for the qeli scripts.

Centralizes the paramiko connection boilerplate and the lab/prod host constants that
were copy-pasted across ~97 scripts in this folder (each defined its own ``connect`` /
``ssh`` / ``run`` and hardcoded the VM IPs). See docs/REFACTOR-PLAN.md (R7).

Passwords are read from the ``QELI_LAB_PASS`` env var — never hardcode credentials.

Usage:
    from lab_common import connect, run, LAB_SRV, LAB_CLI, PROD
    c = connect(LAB_SRV)
    print(run(c, "uptime"))
"""
import os

import paramiko

# Lab VMs (internal) and the production server, as (host, user) tuples. Pass any of
# these straight to connect(); the password comes from QELI_LAB_PASS.
LAB_SRV = ("10.66.116.10", "root")      # server VM (qeli daemon)
LAB_CLI = ("10.66.116.11", "root")      # client VM (Android emulator / build host)
PROD = ("YOUR_PROD_HOST", "root")      # production server


def lab_password():
    """The lab/prod SSH password from the QELI_LAB_PASS environment variable."""
    return os.environ.get("QELI_LAB_PASS", "")


def connect(host, user="root", password=None, timeout=20, attempts=6):
    """Open a paramiko SSH client with the lab's standard policy.

    ``host`` may be a plain address string or a ``(host, user)`` tuple such as
    ``LAB_SRV`` / ``LAB_CLI`` / ``PROD``. The password defaults to ``QELI_LAB_PASS``.

    Retries a few times with backoff: the lab sshd occasionally drops a PRE-AUTH
    connection under connection churn / ``MaxStartups`` — paramiko then raises
    ``SSHException: Error reading SSH protocol banner`` (EOF before the banner). That is
    transient, so a single attempt would fail a whole build for no real reason. Also sets
    ``banner_timeout``/``auth_timeout`` so a momentarily-loaded host isn't cut off early.
    """
    import time
    if isinstance(host, (tuple, list)):
        host, user = host[0], host[1]
    if password is None:
        password = lab_password()
    last = None
    for i in range(max(1, attempts)):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=user, password=password, timeout=timeout,
                           banner_timeout=max(timeout, 30), auth_timeout=max(timeout, 20),
                           look_for_keys=False, allow_agent=False)
            return client
        except Exception as e:  # noqa: BLE001 — retry any connect failure (banner EOF, reset, timeout)
            last = e
            try:
                client.close()
            except Exception:
                pass
            if i < attempts - 1:
                time.sleep(min(2 + i * 2, 10))  # backoff on a transient banner drop
    raise last


def run(ssh, cmd, timeout=60, label=None):
    """Run ``cmd`` over an open client; return combined stdout+stderr (utf-8, rstripped)."""
    if label:
        print(f"  {label}...")
    _stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return (out + err).rstrip()
