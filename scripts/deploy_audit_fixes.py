"""
Sync the locally-edited Rust source to 10.66.116.10 (server) and run
`cargo build --release`, then stream the result back. Edit-only script —
nothing is restarted on the remote.
"""
from __future__ import annotations

raise SystemExit("RETIRED: unsafe fixed-host source deployment; use scripts/lab_sync_build.py.")
