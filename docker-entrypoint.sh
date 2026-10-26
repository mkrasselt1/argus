#!/bin/sh
# Make the data dir writable regardless of how the volume/bind-mount is owned,
# then drop privileges to the unprivileged 'argus' user and run the app.
# This lets operators (e.g. Plesk) simply mount any folder at /data without
# needing to know the container user's UID or run chown on the host.
set -e

D="${SECSCAN_DATA_DIR:-/data}"
mkdir -p "$D" 2>/dev/null || true
chown -R argus:argus "$D" 2>/dev/null || true

# Drop to 'argus' using whatever is available in the base image.
if command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid argus --regid argus --init-groups "$@"
elif command -v runuser >/dev/null 2>&1; then
    exec runuser -u argus -- "$@"
elif command -v gosu >/dev/null 2>&1; then
    exec gosu argus "$@"
else
    exec su argus -s /bin/sh -c 'exec "$@"' -- sh "$@"
fi
