#!/usr/bin/env bash
#
# The AFK loop. Runs once.sh repeatedly until the backlog is empty or a cap is hit.
#
# Caps are mandatory, not optional. Sentinel strings fail, agents get stuck in
# retry cycles, and a loop with no ceiling will happily burn your month's budget
# overnight. Set a hard spend limit at your provider as well.
#
# Usage:
#   ./scripts/loop.sh [--max-iterations N] [--max-minutes M] [--no-sandbox-warning]

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

MAX_ITERATIONS="${MAX_ITERATIONS:-10}"
MAX_MINUTES="${MAX_MINUTES:-120}"
WARN_SANDBOX=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-iterations) MAX_ITERATIONS="${2:?}"; shift 2 ;;
    --max-minutes)    MAX_MINUTES="${2:?}";    shift 2 ;;
    --no-sandbox-warning) WARN_SANDBOX=0; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; export ALLOW_DIRTY; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$MAX_ITERATIONS" =~ ^[0-9]+$ ]] || die "--max-iterations must be a number"
[[ "$MAX_MINUTES"    =~ ^[0-9]+$ ]] || die "--max-minutes must be a number"

require_repo
require "$AGENT_BIN"
init_logs

if (( WARN_SANDBOX )) && [[ ! -f /.dockerenv ]] && [[ -z "${AFK_SANDBOXED:-}" ]]; then
  warn "not running in a container. This loop edits files without asking."
  warn "prefer:  ./scripts/sandbox.sh ./scripts/loop.sh"
  warn "continuing in 5s — ctrl-c to stop"
  sleep 5
fi

# Unattended runs refuse a dirty tree outright. once.sh only warns, because there
# you're watching and can judge. Here you are not: your uncommitted work would be
# absorbed into the agent's commits across several iterations, and untangling that
# afterwards is genuinely painful.
dirty="$(git -C "$REPO_ROOT" status --porcelain)"
if [[ -n "$dirty" ]] && [[ -z "${ALLOW_DIRTY:-}" ]]; then
  n="$(printf '%s\n' "$dirty" | wc -l | tr -d ' ')"
  warn "refusing to start: $n uncommitted file(s)"
  note "the agent commits with 'git add -A' on every green iteration, so your"
  note "work would end up inside its commits, unattended, several times over."
  note ""
  printf '%s\n' "$dirty" | head -10 | sed 's/^/       /' >&2
  (( n > 10 )) && note "... and $(( n - 10 )) more"
  note ""
  note "  git add -A && git commit -m 'wip'     keep it"
  note "  git stash                             set it aside"
  note "  ./scripts/loop.sh --allow-dirty       proceed anyway"
  exit 1
fi

deadline=$(( $(date +%s) + MAX_MINUTES * 60 ))
LOG_FILE="$LOG_DIR/loop-$RUN_ID.log"
start_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"

log "loop $RUN_ID — max $MAX_ITERATIONS iterations, $MAX_MINUTES minutes"
log "logging to $LOG_FILE"

iteration=0
stop_reason="iteration cap reached"

while (( iteration < MAX_ITERATIONS )); do
  iteration=$(( iteration + 1 ))

  if (( $(date +%s) >= deadline )); then
    stop_reason="wall-clock cap reached"
    break
  fi

  remaining="$(eligible_issues afk | wc -l | tr -d ' ')"
  if [[ "$remaining" == "0" ]]; then
    stop_reason="backlog empty"
    break
  fi

  log "--- iteration $iteration/$MAX_ITERATIONS ($remaining eligible) ---"
  {
    printf '\n\n========== iteration %s at %s ==========\n' "$iteration" "$(date -Is)"
  } >> "$LOG_FILE"

  iter_log="$LOG_DIR/loop-$RUN_ID-iter-$iteration.log"

  set +e
  RUN_ID="$RUN_ID-i$iteration" "$SCRIPTS_DIR/once.sh" 2>&1 | tee "$iter_log" >> "$LOG_FILE"
  status=${PIPESTATUS[0]}
  set -e

  if (( status != 0 )); then
    stop_reason="iteration $iteration failed (exit $status)"
    warn "$stop_reason — see $iter_log"
    break
  fi

  if grep -qF "$SENTINEL" "$iter_log"; then
    stop_reason="sentinel reported by agent"
    break
  fi

  # An iteration that produced no commit means the agent is spinning. Stop rather
  # than burn the remaining budget repeating itself.
  if [[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "${last_commit:-$start_commit}" ]]; then
    stop_reason="iteration $iteration produced no commit — agent is not progressing"
    warn "$stop_reason"
    break
  fi
  last_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
done

end_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"

log "stopped: $stop_reason"
log "iterations run: $iteration"
if [[ "$start_commit" != "$end_commit" ]]; then
  log "commits:"
  git -C "$REPO_ROOT" --no-pager log --oneline "$start_commit..$end_commit" >&2
  log "review with:  ./scripts/review.sh $start_commit..$end_commit"
else
  log "no commits produced"
fi
log "still open: $(eligible_issues any | wc -l | tr -d ' ') issue(s)"
