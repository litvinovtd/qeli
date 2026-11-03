#!/bin/sh
# Installed root-owned. systemd owns and removes the private runtime directory.
# The core requires a regular file and may read it more than once at startup.
set -eu
if [ "$#" -ne 1 ] || [ -z "${RUNTIME_DIRECTORY:-}" ] || [ ! -d "$RUNTIME_DIRECTORY" ]; then
    echo "Qeli launcher requires a client executable and a systemd runtime directory." >&2
    exit 1
fi
umask 077
config="$RUNTIME_DIRECTORY/client.conf"
# Noclobber refuses a pre-existing file or symlink, even if this helper is misused.
set -C
cat > "$config"
exec "$1" --config "$config"
