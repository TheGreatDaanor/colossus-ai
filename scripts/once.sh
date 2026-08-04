#!/usr/bin/env bash
#
# One AFK iteration. Picks a single eligible issue, implements it, commits.
#
# Run this repeatedly BEFORE you ever run loop.sh. Read the log each time, fix
# prompts/implement.md where the agent went wrong, run it again. Tuning the prompt
# here is what makes an unattended loop safe.
#
# Usage: ./scripts/once.sh [--dry-run]

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_repo
init_logs

prompt="$(build_prompt "$PROMPTS_DIR/implement.md")"

if (( DRY_RUN )); then
  printf '%s\n' "$prompt"
  printf '\n--- eligible now ---\n' >&2
  eligible_issues afk | while IFS= read -r f; do printf '  %s\n' "$(basename "$f")" >&2; done
  exit 0
fi

require "$AGENT_BIN"

n_eligible="$(eligible_issues afk | wc -l | tr -d ' ')"
if [[ "$n_eligible" == "0" ]]; then
  log "no eligible AFK issues — nothing to do"
  printf '%s\n' "$SENTINEL"
  exit 0
fi

log "$n_eligible eligible AFK issue(s)"

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  warn "working tree is dirty — the agent will commit alongside your changes"
fi

LOG_FILE="$LOG_DIR/once-$RUN_ID.log"
log "logging to $LOG_FILE"

set +e
printf '%s' "$prompt" | run_agent "$IMPLEMENT_MODEL" 2>&1 | tee "$LOG_FILE"
status=${PIPESTATUS[1]}
set -e

if (( status != 0 )); then
  die "agent exited $status — see $LOG_FILE"
fi

if grep -qF "$SENTINEL" "$LOG_FILE"; then
  log "agent reported: $SENTINEL"
fi

log "done"
