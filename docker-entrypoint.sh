#!/bin/sh
# Make the data dir writable, then best-effort drop to the unprivileged 'argus'
# user. This must NEVER crash: on platforms that restrict capabilities (e.g.
# Plesk, rootless/user-namespaced Docker, no-new-privileges) dropping privileges
# can fail — in that case we simply run as the current user instead of exiting.
set -e

D="${SECSCAN_DATA_DIR:-/data}"
mkdir -p "$D" 2>/dev/null || true

if [ "$(id -u)" = "0" ]; then
    # Running as root: fix ownership of the (possibly bind-mounted) data dir.
    chown -R argus:argus "$D" 2>/dev/null || true

    # Try to drop privileges, but only exec a dropper that actually works here.
    if command -v setpriv >/dev/null 2>&1 \
       && setpriv --reuid=argus --regid=argus --clear-groups true 2>/dev/null; then
        exec setpriv --reuid=argus --regid=argus --clear-groups "$@"
    elif command -v runuser >/dev/null 2>&1 && runuser -u argus -- true 2>/dev/null; then
        exec runuser -u argus -- "$@"
    elif command -v gosu >/dev/null 2>&1 && gosu argus true 2>/dev/null; then
        exec gosu argus "$@"
    fi
    # Could not drop privileges on this platform — run as root rather than crash.
fi

exec "$@"
