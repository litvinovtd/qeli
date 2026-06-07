#!/bin/bash
# OBSOLETE — superseded by the built-in CLI.
#
# This script targeted the old JSON config format (/etc/qeli/users.json, JSON
# client configs) which no longer exists — the project migrated to flat-INI — and
# interpolated shell variables straight into a python heredoc (injection-prone).
#
# Use the built-in command instead, which writes the flat-INI users file with a
# proper Argon2id hash and can print a qeli:// share link / QR:
#
#   qeli add-client <username> [--password <pw>] \
#       --config /etc/qeli/server.conf \
#       [--profiles <p1,p2>] [--static-ip <ip>] [--max-sessions <n>] \
#       [--link --host <public-host>]
#
# Server identity (pin on clients):  qeli show-identity --config /etc/qeli/server.conf
echo "add-client.sh is obsolete (project migrated to flat-INI)." >&2
echo "Use: qeli add-client <username> [--password <pw>] --config /etc/qeli/server.conf [--link --host <host>]" >&2
exit 1
