#!/usr/bin/env bash
# Remove old sast-studio:rollback-* images: two versions stay, the one
# running (latest) and the one before it (talk.md #029).
#
#   bash scripts/prune-rollbacks.sh        (KEEP=3 to keep more rollbacks)
#
# Every deploy and every upgrade tags the image it replaces. Nothing removed
# them, and .145 reached 54 of them with 516 MB of disk left. Counted by
# image, not by tag: several tags often point at one image, and counting tags
# would keep fewer real versions than it claims. The images behind latest and
# rollback-previous are never removed. Never fails the caller.
set -uo pipefail

KEEP="${KEEP:-1}"
latest="$(docker images --format '{{.ID}}' sast-studio:latest 2>/dev/null)"
previous="$(docker images --format '{{.ID}}' sast-studio:rollback-previous 2>/dev/null)"

# The image behind rollback-previous is the newest rollback by definition and
# takes the first place. Ranking it by creation time alone failed: a build
# that reuses every layer gets the same timestamp to the second, and the tie
# fell to comparing ids as text.
docker images --format '{{.CreatedAt}}|{{.ID}}|{{.Repository}}:{{.Tag}}' sast-studio 2>/dev/null \
  | grep -E '[|]sast-studio:rollback-[0-9a-f]+$' \
  | sort -r \
  | awk -F'|' -v keep="${KEEP}" -v latest="${latest}" -v previous="${previous}" '
      BEGIN { if (previous != "") rank[previous] = ++n }
      $2 == latest { next }
      { if (!($2 in rank)) rank[$2] = ++n
        if (rank[$2] > keep) print $3 }' \
  | while read -r old; do
      docker rmi "${old}" >/dev/null 2>&1 && echo "  removed ${old}"
    done
docker image prune -f >/dev/null 2>&1
exit 0
