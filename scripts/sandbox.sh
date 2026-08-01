#!/usr/bin/env bash
#
# Run a command inside the Docker sandbox with the repo bind-mounted.
#
# Unattended loops run with permissions pre-accepted. Doing that on your real
# filesystem is the single biggest risk in this workflow — one confused agent and
# your home directory is the blast radius. Run it in here instead.
#
# Usage:
#   ./scripts/sandbox.sh                      # interactive shell
#   ./scripts/sandbox.sh ./scripts/loop.sh --max-iterations 5
#   ./scripts/sandbox.sh --rebuild            # force image rebuild

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require docker
require_repo

IMAGE="${SANDBOX_IMAGE:-afk-sandbox:$(basename "$REPO_ROOT")}"
REBUILD=0

if [[ "${1:-}" == "--rebuild" ]]; then REBUILD=1; shift; fi

if (( REBUILD )) || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "building $IMAGE"
  docker build \
    --build-arg UID="$(id -u 2>/dev/null || echo 1001)" \
    --build-arg GID="$(id -g 2>/dev/null || echo 1001)" \
    -t "$IMAGE" \
    -f "$SCRIPTS_DIR/Dockerfile" \
    "$SCRIPTS_DIR"
fi

# Forward only the credentials the agent needs. Never mount your whole home dir.
declare -a env_args=()
for var in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL \
           OPENAI_API_KEY AGENT_BIN IMPLEMENT_MODEL REVIEW_MODEL \
           MAX_ITERATIONS MAX_MINUTES SENTINEL; do
  [[ -n "${!var:-}" ]] && env_args+=(-e "$var=${!var}")
done

if [[ -z "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  warn "no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in env — the agent will not authenticate"
fi

declare -a tty_args=()
[[ -t 0 && -t 1 ]] && tty_args=(-it)

if [[ $# -eq 0 ]]; then set -- bash; fi

log "running in $IMAGE: $*"

exec docker run --rm "${tty_args[@]}" \
  -v "$REPO_ROOT:/repo" \
  -w /repo \
  --network bridge \
  --memory="${SANDBOX_MEMORY:-8g}" \
  --cpus="${SANDBOX_CPUS:-4}" \
  "${env_args[@]}" \
  "$IMAGE" \
  "$@"
