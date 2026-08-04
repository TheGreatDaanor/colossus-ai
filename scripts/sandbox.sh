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

  # A build can succeed and still produce an image that cannot start — a USER
  # that does not resolve is the classic case. Find out here, with a message
  # that says what to do, rather than mid-loop from the daemon.
  if ! err="$(docker run --rm "$IMAGE" true 2>&1)"; then
    warn "image built but will not start:"
    printf '  %s\n' "$err" >&2
    case "$err" in
      *"unable to find user"*|*"no matching entries in passwd"*)
        die "the container user does not exist in the image.
       Your host uid ($(id -u)) probably collides with a user already in the base
       image. Update scripts/Dockerfile to the current version, which resolves
       the user numerically, then rebuild:
           ./scripts/sandbox.sh --rebuild"
        ;;
      *)
        die "see the error above; fix scripts/Dockerfile and rebuild"
        ;;
    esac
  fi
  log "image starts cleanly"
fi

# Forward only the credentials the agent needs. Never mount your whole home dir.
declare -a env_args=()
for var in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL \
           OPENAI_API_KEY AGENT_BIN IMPLEMENT_MODEL REVIEW_MODEL \
           MAX_ITERATIONS MAX_MINUTES SENTINEL; do
  [[ -n "${!var:-}" ]] && env_args+=(-e "$var=${!var}")
done

# Two ways to authenticate, and they bill differently:
#
#   ANTHROPIC_API_KEY   -> pay-per-token API credits
#   claude.ai login     -> your Pro/Max subscription
#
# If you have a subscription, an exported API key silently diverts unattended loops
# onto metered credits. So prefer forwarding the existing login when there's one,
# and only fall back to the key.
declare -a cred_args=()
CLAUDE_CREDS="${CLAUDE_CREDS:-$HOME/.claude/.credentials.json}"

if [[ -n "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  if [[ -f "$CLAUDE_CREDS" ]] && [[ -z "${FORCE_API_KEY:-}" ]]; then
    warn "both an API key and a claude.ai login are present"
    note "the API key wins, so this run bills to pay-per-token credits, not your"
    note "subscription. To use the subscription instead:"
    note "    unset ANTHROPIC_API_KEY   (then re-run)"
    note "to silence this and keep using the key:  FORCE_API_KEY=1"
  fi
elif [[ -f "$CLAUDE_CREDS" ]]; then
  # Mount the login read-only so the container inherits the subscription session.
  cred_args=(-v "$CLAUDE_CREDS:/home/agent/.claude/.credentials.json:ro")
  log "no API key — forwarding your claude.ai login (subscription billing)"
else
  warn "no ANTHROPIC_API_KEY and no claude.ai login at $CLAUDE_CREDS"
  note "the agent will not authenticate inside the container. Either:"
  note "    export ANTHROPIC_API_KEY=sk-...      (pay-per-token)"
  note "    run 'claude' once on the host        (subscription, then re-run this)"
fi

declare -a tty_args=()
[[ -t 0 && -t 1 ]] && tty_args=(-it)

if [[ $# -eq 0 ]]; then set -- bash; fi

log "running in $IMAGE: $*"

exec docker run --rm "${tty_args[@]}" \
  -v "$REPO_ROOT:/repo" \
  "${cred_args[@]}" \
  -w /repo \
  --network bridge \
  --memory="${SANDBOX_MEMORY:-8g}" \
  --cpus="${SANDBOX_CPUS:-4}" \
  "${env_args[@]}" \
  "$IMAGE" \
  "$@"
