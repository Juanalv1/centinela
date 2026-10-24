#!/bin/sh
# Victim "company server" entrypoint. Runs as root only long enough to:
#  1. start the protected `db-sim` process AS ROOT (a copy of /bin/sleep, so its
#     process name is literally `db-sim`), and
#  2. drop privileges and exec the API as the unprivileged `app` user.
# Even if the executor were tricked into targeting db-sim, the kernel returns
# EPERM because `app` cannot signal a root-owned process.
set -eu

db-sim infinity &

exec setpriv --reuid=app --regid=app --init-groups \
    python -m uvicorn app:app --host 0.0.0.0 --port "${PORT:-8000}" --no-access-log
