#!/usr/bin/env bash
# Turn on scanner upgrades from the web panel (Monitor tab).
#
#   bash scripts/install-updater.sh             set up (safe to re-run)
#   bash scripts/install-updater.sh --remove    turn it off again
#
# Creates ops/, the directory the app and the host updater exchange a request
# and its progress through, and a crontab entry that runs
# scripts/sast_updater.py every minute as this user. No sudo, no system
# service: the updater needs docker (this user's docker group) and the
# repository, nothing more.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The path goes into a crontab line, run by /bin/sh, where "%" means newline
# and no quoting is safe for every character. Plain paths only.
if ! printf '%s' "${ROOT}" | grep -Eq '^[A-Za-z0-9/._-]+$'; then
  echo "  ${ROOT}: move the repository to a path of letters, digits and / . _ -" >&2
  exit 1
fi
LINE="* * * * * cd ${ROOT} && /usr/bin/env python3 scripts/sast_updater.py >/dev/null 2>&1"
MARK="scripts/sast_updater.py"

current_crontab() { crontab -l 2>/dev/null || true; }

if [ "${1:-}" = "--remove" ]; then
  current_crontab | grep -vF "${MARK}" | crontab -
  echo "  upgrades from the web panel are off (ops/ is left in place)"
  exit 0
fi

# Never in root's crontab: the updater is a script in this repository, and
# it acts on requests the container writes into ops/. As root, whoever can
# edit either would run code as root.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "${ROOT}/ops"
  echo "  not scheduling the updater as root; run this as the account that owns" >&2
  echo "  the repository (in the docker group)" >&2
  exit 1
fi

# ops/ first, before anything that can stop this script: compose mounts it,
# and a missing bind-mount source is created by Docker as root, which
# neither the app nor the updater can write to afterwards.
mkdir -p "${ROOT}/ops"
# The app writes here as uid 1000 (appuser in the image). When this user is
# someone else, the app needs write access some other way.
if [ "$(id -u)" != "1000" ]; then
  # Sticky, like /tmp: others may add files but not replace this user's.
  chmod 1777 "${ROOT}/ops"
  echo "  ! you are uid $(id -u), the app is uid 1000: ops/ made writable to all."
  echo "  !   The updater treats everything in it as untrusted input; keep this"
  echo "  !   directory's parents closed to other accounts (chmod 750 ~)."
fi

command -v crontab >/dev/null 2>&1 || { echo "  crontab not found; install cron" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  python3 not found" >&2; exit 1; }

if current_crontab | grep -qF "${MARK}"; then
  echo "  updater already scheduled"
else
  { current_crontab; echo "${LINE}"; } | crontab -
  echo "  updater scheduled: every minute, as $(id -un)"
fi
