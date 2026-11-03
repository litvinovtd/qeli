"""Read-only push-CI admission for the exact local release commit."""
import json
from pathlib import Path
import re
import subprocess


def _query(root, command, timeout):
    result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"{command[0]} exit {result.returncode}")
    return result.stdout



def _emit_failed_jobs(root, run, emit):
    # Diagnostics cannot authorize a failed workflow or stop the later gates.
    run_id = run.get("databaseId")
    if type(run_id) is not int or run_id <= 0:
        emit("  ! failed-job details unavailable: no valid workflow run ID")
        return
    try:
        response = json.loads(_query(root, ["gh", "run", "view", str(run_id), "--json", "jobs"], 120))
        if not isinstance(response, dict) or not isinstance(response.get("jobs"), list):
            raise RuntimeError("invalid CI jobs response")
        for job in response["jobs"]:
            if not isinstance(job, dict):
                raise RuntimeError("invalid CI job")
            if job.get("conclusion") not in ("success", "skipped", None):
                emit(f"    FAILED: {job.get('name', '<unnamed>')} = {job['conclusion']}")
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        emit(f"  ! failed-job details unavailable: {error}")


def check_release_ci(root, branch, emit=print, *, by_commit=False):
    """A missing command, identity or valid CI response cannot qualify a release."""
    root = Path(root)
    failures = []
    try:
        if not by_commit and (not isinstance(branch, str) or not branch.strip() or branch == "HEAD"):
            raise RuntimeError("release branch is unavailable; pass its name explicitly")
        # Establish local identity before GitHub: empty stdout from a failed git
        # command must never skip the comparison with the workflow commit.
        head = _query(root, ["git", "rev-parse", "HEAD^{commit}"], 30).strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
            raise RuntimeError("git returned an invalid release commit identity")
        runs = json.loads(_query(root, [
            "gh", "run", "list", "--commit" if by_commit else "--branch",
            head if by_commit else branch, "--workflow", "CI", "--event", "push",
            "--limit", "1", "--json", "conclusion,status,headSha,databaseId,event",
        ], 120))
        if not isinstance(runs, list):
            raise RuntimeError("CI response must be a list of workflow runs")
        if not runs:
            raise RuntimeError("no push CI run found for the selected release source")
        run = runs[0]
        if not isinstance(run, dict):
            raise RuntimeError("CI response contains an invalid workflow run")
        # PR runs usually test a synthetic merge tree, not this head commit.
        if run.get("event") != "push":
            raise RuntimeError("release coverage requires a push CI run; PR/manual/scheduled runs cannot qualify it")
        sha = run.get("headSha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise RuntimeError("CI run has no valid headSha; release coverage is unknown")
        status, conclusion = run.get("status"), run.get("conclusion")
        if not isinstance(status, str) or not status:
            raise RuntimeError("CI run has no valid status")
        emit(f"  {sha[:8]}  status={status}  conclusion={conclusion}")
        if sha != head:
            failures.append(
                f"CI ran on {sha[:8]}, not on the commit being released ({head[:8]}) "
                "- push and let CI finish first")
        if status != "completed":
            failures.append(f"CI still running ({status})")
        elif conclusion != "success":
            failures.append(f"CI conclusion={conclusion}")
            _emit_failed_jobs(root, run, emit)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        failures.append(f"CI admission failed: {error}")
        emit(f"  ! {error}")
    return failures
