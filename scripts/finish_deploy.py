#!/usr/bin/env python3
"""Retired unsafe one-host deployment recipe.

Use install-qeli-server.sh or the documented package workflow.  The old script mixed
system configuration, firewall mutation, user creation and a fixed example credential.
Keeping it executable would make an accidental invocation look like a supported deploy.
"""

raise SystemExit(
    "RETIRED: use install-qeli-server.sh and the documented add-client workflow"
)
