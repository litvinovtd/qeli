"""Shared SSH host-key policy for the lab build/deploy scripts.

Every `scripts/build_*.py` and `scripts/deploy_*.py` used to open its lab connection with
`paramiko.AutoAddPolicy()` and then send the root password. That accepts whatever answers on
the address — anyone able to spoof/ARP/DNS-hijack the lab segment collects the root password
and, worse, gets to hand these scripts the artefacts they ship: `qeli.dll`,
`libqeli.dylib`, `libqeli.so`. Those land in `native-libs/` and in the Android/Windows/macOS
client trees, and `verify.sh --update` + `provenance.py --update` then stamp them as
canonical, so a reviewer only sees a changed hash — which is exactly what a legitimate
rebuild produces. A build machine that authenticates its peer is the cheapest possible
defence against that, and the fix already existed: `release_preflight.py` did it in audit
2026-07-27 (O8) and nothing else picked it up. (Audit 2026-08-04, H-11.)

Usage:

    from ssh_hostkey import harden
    c = paramiko.SSHClient()
    harden(c, host)
    c.connect(host, username="root", password=pw, look_for_keys=False, allow_agent=False)

Set `QELI_LAB_TRUST_NEW_HOST=1` for the one-off first connection to a rebuilt lab box; it
prints a warning so the relaxation is never silent.
"""

import os


def harden(client, host: str = "") -> None:
    """Honour known_hosts and refuse an unknown key unless explicitly told otherwise."""
    import paramiko

    client.load_system_host_keys()
    try:
        client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
    except OSError:
        pass
    if os.environ.get("QELI_LAB_TRUST_NEW_HOST") == "1":
        print(f"  ! QELI_LAB_TRUST_NEW_HOST=1 — accepting an unverified host key for {host}")
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
