#!/usr/bin/env bash
# Write the host's real docker group id into .env, so the container can read
# the docker socket that the Monitor tab needs.
#
#   bash scripts/docker-gid.sh
#
# The socket is owned by root:docker with no world access, and the app runs as
# a non-root user, so it needs that group. The gid differs between hosts (988
# on one, 999 on another), which is why compose reads it from .env instead of
# hardcoding it.
#
# This lives in its own file because both entry points need it and only one
# used to do it: `setup.sh --docker` went straight to `compose up`, so the
# first container on a clean machine was created before any DOCKER_GID
# existed and silently took the fallback. Compose only reads .env when it
# creates a container, so that container then kept the wrong group for its
# whole life and the Monitor tab reported "permission denied" no matter how
# many times the service was restarted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [ ! -S /var/run/docker.sock ]; then
  echo "  no docker socket on this host; the Monitor tab will show it as off"
  exit 0
fi

DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
echo "  docker.sock is group ${DOCKER_GID}"

# A .env this user cannot write stops the deploy dead, and under set -e the
# only clue is one "Permission denied" line among the build output. It happens
# for a mundane reason: one deploy run with sudo leaves the file owned by
# root, and every later run as a normal user fails.
if [ -e .env ] && [ ! -w .env ]; then
  echo "  ! cannot write .env -- it belongs to $(stat -c '%U' .env), you are $(id -un)" >&2
  echo "  !   sudo chown $(id -un):$(id -gn) $(pwd)/.env" >&2
  echo "  ! (a previous deploy run with sudo is the usual cause)" >&2
  echo "FAILED: fix the ownership of .env and run this again" >&2
  exit 1
fi

if [ -f .env ] && grep -q '^DOCKER_GID=' .env; then
  # Portable in-place edit: BSD and GNU sed disagree about -i.
  tmp="$(mktemp)"
  sed "s/^DOCKER_GID=.*/DOCKER_GID=${DOCKER_GID}/" .env > "${tmp}" \
    && mv "${tmp}" .env \
    || { echo "FAILED: could not update DOCKER_GID in .env" >&2; exit 1; }
else
  echo "DOCKER_GID=${DOCKER_GID}" >> .env \
    || { echo "FAILED: could not write DOCKER_GID to .env" >&2; exit 1; }
fi
echo "  wrote DOCKER_GID=${DOCKER_GID} to .env"

# A container created before .env had the right gid keeps the old group for
# its whole life, because compose only reads .env at creation time. Restarting
# does not fix it and neither does `up -d` on its own, since compose sees a
# container whose config it believes is current. Report the mismatch so the
# caller can force a recreate rather than leaving the Monitor tab broken.
if command -v docker >/dev/null 2>&1; then
  for name in $(docker ps -a --filter 'name=sast-studio' --format '{{.Names}}' 2>/dev/null); do
    have="$(docker inspect "${name}" --format '{{range .HostConfig.GroupAdd}}{{.}} {{end}}' 2>/dev/null || true)"
    case " ${have} " in
      *" ${DOCKER_GID} "*) ;;
      *)
        echo "  ! ${name} was created with group [${have% }], not ${DOCKER_GID}"
        echo "  !   it needs recreating before the Monitor tab can read stats"
        exit 2 ;;
    esac
  done
fi
