#!/usr/bin/env bash
# One command to update a running deployment: cache, build, switch, verify.
#
#   ./scripts/deploy.sh              # pull, cache, build, restart, verify
#   ./scripts/deploy.sh --no-pull    # deploy the working tree as it is
#   ./scripts/deploy.sh --rollback   # go back to the previous image
#
# The build runs while the old containers keep serving, so the only downtime
# is the container swap at the end. The previous image is tagged first, so a
# bad deploy can be undone without rebuilding anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

PULL=1
ROLLBACK=0
for arg in "$@"; do
  case "${arg}" in
    --no-pull)  PULL=0 ;;
    --rollback) ROLLBACK=1 ;;
    -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: ${arg}" >&2; exit 2 ;;
  esac
done

step() { printf '\n== %s\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  else docker-compose "$@"; fi
}

# ------------------------------------------------------------------ rollback
if [ "${ROLLBACK}" -eq 1 ]; then
  step "Rolling back to the previous image"
  docker image inspect sast-studio:rollback-previous >/dev/null 2>&1 \
    || die "no rollback image found (nothing to roll back to)"
  docker tag sast-studio:rollback-previous sast-studio:latest
  compose up -d --no-build || die "could not start the previous image"
  echo "Rolled back. Check the service, then redeploy when the fix is ready."
  exit 0
fi

# -------------------------------------------------------------------- deploy
step "Tagging the current image so this deploy can be undone"
if docker image inspect sast-studio:latest >/dev/null 2>&1; then
  PREV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  docker tag sast-studio:latest "sast-studio:rollback-${PREV}"
  docker tag sast-studio:latest sast-studio:rollback-previous
  echo "  previous image kept as sast-studio:rollback-${PREV}"
else
  echo "  no existing image (first deploy)"
fi

if [ "${PULL}" -eq 1 ] && [ -d .git ]; then
  step "Updating the source"
  git pull --ff-only || die "git pull failed (local changes? resolve them first)"
fi
echo "  deploying $(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"

# The Monitor tab reads the docker socket, which is owned by root:docker with
# no world access. The app runs as a non-root user, so it needs that group --
# and the gid differs between hosts, so read the real one rather than guessing.
# Without this the Monitor tab just says "permission denied".
step "Detecting the docker group id for the Monitor tab"
# Exit 2 means a running container still carries the old group. Compose
# reads .env only when it creates a container, so writing the right gid is
# not enough on its own -- that container has to be recreated, or the
# Monitor tab stays broken however often the service is restarted.
RECREATE_FOR_GID=0
# Capture the status directly. Inside `if ! cmd`, $? is the status of the
# negation rather than the command, so the exit-2 signal was read as 0 and
# a stale container aborted the deploy instead of being recreated.
# `|| rc=$?` also keeps set -e from killing the script on a non-zero exit.
rc=0
bash "${ROOT}/scripts/docker-gid.sh" || rc=$?
case "${rc}" in
  0) ;;
  2) RECREATE_FOR_GID=1 ;;
  *) die "could not determine the docker group id" ;;
esac

# Download the scanner binaries before the build rather than during it. On a
# slow link this is the difference between a build of minutes and one of tens
# of minutes, and a failure here costs nothing: the build falls back to
# downloading whatever is still missing.
step "Caching scanner binaries (resumable, safe to interrupt)"
bash "${ROOT}/scripts/fetch-vendor.sh" || echo "  continuing; the build will fetch what is missing"

step "Building the new image (the running service is untouched)"
compose build || die "build failed -- the old version is still serving"

step "Switching to the new image"
if [ "${RECREATE_FOR_GID}" -eq 1 ]; then
  echo "  forcing a recreate so the corrected docker group takes effect"
  compose up -d --force-recreate sast-studio \
    || die "could not start the new image; ./scripts/deploy.sh --rollback"
fi
compose up -d || die "could not start the new image; ./scripts/deploy.sh --rollback"

# nginx.conf is bind-mounted as a single file, which pins the inode it had
# when the container started. git pull replaces the file rather than editing
# it in place, so the container keeps serving the old config and even
# "nginx -s reload" re-reads the stale inode. Compose will not recreate it
# either, because the image has not changed. Recreate it when the file
# differs. (Found when a Host-header fix deployed and silently did nothing.)
if ! compose exec -T nginx cmp -s /etc/nginx/conf.d/default.conf /dev/stdin        < "${ROOT}/nginx/nginx.conf" 2>/dev/null; then
  echo "  nginx config changed on disk; recreating the container"
  compose up -d --force-recreate nginx || die "could not restart nginx"
fi

step "Waiting for the service to report healthy"
ok=0
for _ in $(seq 1 60); do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
           "$(compose ps -q sast-studio 2>/dev/null)" 2>/dev/null || echo unknown)"
  case "${state}" in
    healthy|running) ok=1; break ;;
    unhealthy)       break ;;
  esac
  sleep 5
done
[ "${ok}" -eq 1 ] || die "service did not become healthy -- ./scripts/deploy.sh --rollback"

step "Checking the app answers"
URL="http://localhost:8080"
code="$(curl -s -o /dev/null -w '%{http_code}' "${URL}/api/health" || echo 000)"
[ "${code}" = "200" ] || die "health endpoint returned ${code} -- ./scripts/deploy.sh --rollback"

# /api/tools needs a login once accounts are enabled, so a 401 here is the
# system working, not a failure. Report the scanner count when it is readable
# and say why when it is not, rather than failing a healthy deployment.
tools_code="$(curl -s -o /tmp/sast-tools.$$ -w '%{http_code}' "${URL}/api/tools" || echo 000)"
if [ "${tools_code}" = "200" ]; then
  tools_ok="$(grep -o '"available": *true' /tmp/sast-tools.$$ | wc -l | tr -d ' ')"
  echo "  health 200; ${tools_ok}/6 scanners available"
elif [ "${tools_code}" = "401" ]; then
  echo "  health 200; /api/tools requires a sign-in (accounts are enabled)"
else
  rm -f /tmp/sast-tools.$$
  die "/api/tools returned ${tools_code} -- ./scripts/deploy.sh --rollback"
fi
rm -f /tmp/sast-tools.$$

# On a first run the application generates an administrator password and
# prints it once. Surface it here rather than leaving it buried in the log:
# it is not stored anywhere readable, so a missed line means resetting it.
if compose logs sast-studio 2>/dev/null | grep -q "First run: created administrator"; then
  step "First run: administrator account"
  compose logs sast-studio 2>/dev/null \
    | grep -A 4 "First run: created administrator" \
    | sed 's/^[^|]*| *//'
  echo "  Save these now; the password is not recoverable."
fi

printf '\nDeployed. %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
echo "Open ${URL} -- roll back with ./scripts/deploy.sh --rollback"
