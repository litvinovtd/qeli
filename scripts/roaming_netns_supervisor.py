#!/usr/bin/env python3
"""Supervise one private unshare job; interruption must remove its descendants."""
import ctypes
import os
import signal
import subprocess
import sys


def main(argv):
    if not argv or os.name != "posix":
        print("roaming namespace supervisor requires Linux and a command", file=sys.stderr)
        return 2
    # Signals arriving during fork/setup are delivered only after the owned child
    # and handlers are registered. The child restores the caller's signal mask.
    interrupted = {signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, interrupted)
    parent_pid = os.getpid()
    libc = ctypes.CDLL(None, use_errno=True)

    def prepare_child():
        # Linux PR_SET_PDEATHSIG. This also covers SIGKILL of this supervisor:
        # supervisor -> unshare -> private PID init -> all private descendants.
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot set parent-death signal")
        if os.getppid() != parent_pid:
            os._exit(125)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    try:
        child = subprocess.Popen(argv, preexec_fn=prepare_child, start_new_session=True)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"cannot start isolated roaming runner: {error}", file=sys.stderr)
        return 2

    class Interrupted(Exception):
        pass

    def stop(signum, _frame):
        # Unwind Popen.wait first: calling wait again inside its signal handler
        # would try to acquire the same waitpid lock and deadlock.
        raise Interrupted(signum)

    for signum in interrupted:
        signal.signal(signum, stop)
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask - interrupted)
        status = child.wait()
    except Interrupted as error:
        signal.pthread_sigmask(signal.SIG_BLOCK, interrupted)
        # util-linux may block TERM/INT while waiting. Kill only this Popen
        # child; its wait status prevents signaling a reused PID.
        child.kill()
        child.wait()
        return 128 + error.args[0]
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
