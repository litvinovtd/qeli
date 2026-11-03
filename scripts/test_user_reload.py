#!/usr/bin/env python3
"""Q06 live revoke and file/inline reload regression. Requires an explicit binary/SHA; never stops host services."""
# Manual lab scenario: importing for test discovery must not execute it.
if __name__ == "__main__":
    from audit_q06_cases import run_cases

    if __name__ == "__main__":
        run_cases(__doc__, ('users-live', 'users-durability'))
