#!/usr/bin/env python3
"""Compatibility entry point for isolated Q05 panel live-reload verification.

Requires --qeli, --sha256 and --output. The shared runner preserves running services
and executes the runtime scenario in private NET/mount/PID namespaces.
"""
# Manual lab scenario: importing for test discovery must not execute it.
if __name__ == "__main__":
    from pathlib import Path
    import subprocess
    import sys

    if __name__ == "__main__":
        root = Path(__file__).resolve().parent.parent
        raise SystemExit(subprocess.call([
            sys.executable, str(root / "scripts/audit_web_auth_lab.py"), *sys.argv[1:],
            "--audit", "q05", "--fixture", str(root / "scripts/audit_web_transactions.py"),
            "--scenario", "runtime",
        ], cwd=root))
