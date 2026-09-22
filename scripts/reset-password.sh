#!/usr/bin/env bash
# Reset a forgotten password from the host.
#
#   ./scripts/reset-password.sh                  # reset admin, prompt for it
#   ./scripts/reset-password.sh alice            # reset a named account
#   ./scripts/reset-password.sh admin --generate # make one up and print it
#   ./scripts/reset-password.sh --list           # who has an account here
#
# There is no "forgot password" link on the login page, because sending one
# needs mail the deployment does not have. Shell access on the host is the
# recovery path instead: it is strictly more access than the login gives, so
# it is a reasonable thing to require, and it leaves a trace in shell history
# where a self-service reset link would leave none.
#
# The password is typed at a prompt or generated. It is never an argument:
# arguments are visible in `ps` and land in .bash_history.
set -euo pipefail

# Everything below runs from the project root, so this works whether it is
# invoked as ./scripts/reset-password.sh or from inside scripts/.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}" || { echo "cannot enter ${ROOT}" >&2; exit 1; }

USERNAME=""
GENERATE=0
LIST=0
for arg in "$@"; do
  case "${arg}" in
    --generate|-g) GENERATE=1 ;;
    --list|-l)     LIST=1 ;;
    -h|--help)     sed -n '2,16p' "$0"; exit 0 ;;
    -*)            echo "unknown option: ${arg}" >&2; exit 2 ;;
    *)
      [ -n "${USERNAME}" ] && { echo "one account at a time" >&2; exit 2; }
      USERNAME="${arg}"
      ;;
  esac
done
USERNAME="${USERNAME:-admin}"

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

# Where to run: inside the running container if there is one, otherwise the
# local checkout. Getting this wrong writes to the wrong database and looks
# like the reset silently did nothing.
compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  else docker-compose "$@"; fi
}

RUNNING=0
if command -v docker >/dev/null 2>&1 \
   && compose ps --status running 2>/dev/null | grep -q sast-studio; then
  RUNNING=1
fi

run_py() {   # stdin is the password; $1 is the username, $2 the mode flag
  if [ "${RUNNING}" = "1" ]; then
    # The image only ships app/, so the helper is fed to the interpreter on
    # the command line and the password still arrives on stdin. Keeping the
    # helper out of the image also keeps a password-reset tool off the box
    # that serves the web app.
    compose exec -T -e "RESET_USER=$1" -e "RESET_LIST=${2:-0}" sast-studio \
      python -c "$(cat "${ROOT}/scripts/_reset_password.py")"
  else
    if [ ! -d .venv ]; then
      echo "  No sast-studio container is running, and there is no .venv here," >&2
      echo "  so there is nothing to read the account database from." >&2
      echo >&2
      echo "  What is running right now:" >&2
      compose ps 2>&1 | sed 's/^/    /' >&2
      echo >&2
      echo "  If a deploy or ./setup.sh --update is in progress, the container" >&2
      echo "  is briefly down -- wait for it to come back and run this again:" >&2
      echo "      docker compose ps           # until sast-studio is healthy" >&2
      echo >&2
      echo "  If it is not meant to be down, start it:" >&2
      echo "      cd $(pwd) && docker compose up -d" >&2
      die "no running container"
    fi
    RESET_USER="$1" RESET_LIST="${2:-0}" ./.venv/bin/python \
      scripts/_reset_password.py
  fi
}

if [ "${LIST}" = "1" ]; then
  echo "Accounts on this deployment:"
  </dev/null run_py "" 1
  exit 0
fi

if [ "${RUNNING}" = "1" ]; then
  echo "Resetting '${USERNAME}' in the running container."
elif [ -d .venv ]; then
  echo "No running container found; using the local checkout."
else
  # Fail before asking for a password we have nowhere to store. Discovering
  # this after typing it twice is the version of this that annoyed someone.
  echo "  No sast-studio container is running, and there is no .venv here," >&2
  echo "  so there is nowhere to store a new password." >&2
  echo >&2
  echo "  What is running right now:" >&2
  compose ps 2>&1 | sed 's/^/    /' >&2
  echo >&2
  echo "  A deploy or ./setup.sh --update takes the container down briefly." >&2
  echo "  Wait for it to report healthy, then run this again:" >&2
  echo "      docker compose ps" >&2
  echo >&2
  echo "  If it should be running and is not:" >&2
  echo "      cd $(pwd) && docker compose up -d" >&2
  die "no running container"
fi

if [ "${GENERATE}" = "1" ]; then
  # No pipe: whatever reads the tail of /dev/urandom closes the pipe early
  # and kills the writer with SIGPIPE, which pipefail turns into a fatal
  # error. Read a bounded chunk, then filter in the shell. The suffix
  # guarantees the character classes a policy may require, whatever the
  # random part happened to produce.
  # base64 rather than raw bytes: command substitution strips null bytes and
  # warns about them, and /dev/urandom is full of them.
  RAND="$(head -c 64 /dev/urandom | base64 | LC_ALL=C tr -cd 'A-Za-z0-9')"
  RAND="${RAND:0:20}"
  [ ${#RAND} -ge 16 ] || die "could not read randomness from /dev/urandom"
  PASSWORD="${RAND}Aa1!"
  GENERATED=1
else
  GENERATED=0
  # -s so it is not echoed; </dev/tty so this still works when the script
  # itself is being piped.
  printf 'New password for %s: ' "${USERNAME}" >&2
  read -rs PASSWORD </dev/tty; echo >&2
  printf 'Again: ' >&2
  read -rs CONFIRM </dev/tty; echo >&2
  [ "${PASSWORD}" = "${CONFIRM}" ] || die "the two passwords do not match"
  [ -n "${PASSWORD}" ] || die "empty password"
fi

if printf '%s' "${PASSWORD}" | run_py "${USERNAME}"; then
  if [ "${GENERATED}" = "1" ]; then
    echo
    echo "  password: ${PASSWORD}"
    echo "  (shown once -- copy it now, then change it after signing in)"
  fi
  echo
  echo "Sign in, then change this password from Settings -> Account."
else
  die "the password was not changed"
fi
