"""Common read-only admission of committed release source."""
from __future__ import annotations
import re
import subprocess


def source_identity(root, *, allow_new_evidence=False):
    """Reject dirty source and Git flags that can hide tracked worktree edits.

    Certification may write new, untracked evidence inside its excluded subtree.
    Tracked evidence edits still require a commit; ignored caches are not inputs.
    """
    def query(*args):
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=30)
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(detail or "Release Git identity query failed")
        return result.stdout

    commit = query("rev-parse", "--verify", "HEAD^{commit}").decode("utf-8", errors="replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise RuntimeError("invalid release commit identity")
    # NUL records avoid ambiguity from quoted paths or embedded newlines.
    flags = query("ls-files", "-v", "-z").split(b"\0")
    if any(row and (97 <= row[0] <= 122 or row[0] == ord("S")) for row in flags):
        raise RuntimeError("Release source has assume-unchanged/skip-worktree Git flags")
    status = query("status", "--porcelain", "-z", "--untracked-files=all").split(b"\0")
    if any(row and not (allow_new_evidence and
                       row.startswith(b"?? release/certification/")) for row in status):
        raise RuntimeError("Release admission requires a clean committed working tree")
    return commit
