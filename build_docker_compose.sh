#!/bin/bash
# Reproducible build using the inputs in reproducible.env.
set -uo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./reproducible.env
set +a
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

[ -d .git ] && find . -path ./.git -prune -o -exec chmod go-w {} +

BAKE_SET=()
while IFS='=' read -r key value; do
  case "$key" in ''|\#*) continue;; esac
  BAKE_SET+=(--set "*.args.${key}=${value}")
done < <(grep -vE '^[[:space:]]*(#|$)' reproducible.env)
BAKE_SET+=(--set "*.args.SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}")

if docker --help | grep -q buildx; then
  if docker buildx inspect super-builder >/dev/null 2>&1; then
    CURRENT_BUILDKIT=$(docker buildx inspect super-builder \
      | sed -n 's/.*image="\([^"]*\)".*/\1/p' | head -1)
    if [ -n "${BUILDKIT_REF:-}" ] && [ "$CURRENT_BUILDKIT" != "$BUILDKIT_REF" ]; then
      docker buildx rm super-builder
    fi
  fi
  docker buildx create --name super-builder --driver docker-container \
    --driver-opt "image=${BUILDKIT_REF}" 2>/dev/null || true
  OUTPUT="type=docker,rewrite-timestamp=true"
  ARGS=()
  for arg in "$@"; do
    case "$arg" in
      --load) ;;
      --push) OUTPUT="type=registry,rewrite-timestamp=true" ;;
      *) ARGS+=("$arg") ;;
    esac
  done
  docker buildx bake --builder super-builder --file docker-compose.yml \
    "${BAKE_SET[@]}" --set "*.output=${OUTPUT}" ${ARGS[@]+"${ARGS[@]}"}
else
  export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1
  docker compose build "$@"
fi
