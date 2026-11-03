#!/usr/bin/env python3
"""Q06 static IP, group bandwidth metadata, ACL/source revoke and device caps. Includes sustained throughput checks; not a release performance benchmark."""
# Manual lab scenario: importing for test discovery must not execute it.
if __name__ == "__main__":
    from audit_q06_cases import run_cases

    if __name__ == "__main__":
        run_cases(__doc__, ('users-live', 'users-policy', 'users-admission', 'users-bandwidth'))
