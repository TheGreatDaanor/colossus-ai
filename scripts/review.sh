#!/usr/bin/env bash
#
# Review a diff in a FRESH context with the stronger model.
#
# Why a separate process: an implementation session ends deep in the dumb zone, so
# a reviewer spawned inside it is dumber than the thing that wrote the code. This
# starts clean and pushes the coding standards in alongside the diff — judging needs
# the rubric in hand, writing does not.
#
# Usage:
#   ./scripts/review.sh                 # working tree vs HEAD
#   ./scripts/review.sh main..HEAD      # any git range
#   ./scripts/review.sh abc123 def456

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_repo
require "$AGENT_BIN"
init_logs

case $# in
  0) range=""; diff_desc="uncommitted changes" ;;
  1) range="$1"; diff_desc="$1" ;;
  2) range="$1..$2"; diff_desc="$1..$2" ;;
  *) die "usage: review.sh [range | from to]" ;;
esac

if [[ -z "$range" ]]; then
  diff="$(git -C "$REPO_ROOT" diff HEAD)"
else
  diff="$(git -C "$REPO_ROOT" diff "$range")"
fi

[[ -n "$diff" ]] || die "empty diff for: $diff_desc"

diff_bytes=${#diff}
if (( diff_bytes > 400000 )); then
  warn "diff is ${diff_bytes} bytes — this will push the reviewer into the dumb zone"
  warn "review it in smaller ranges instead"
fi

standards="(no coding-standards skill found at $STANDARDS_FILE)"
[[ -f "$STANDARDS_FILE" ]] && standards="$(cat "$STANDARDS_FILE")"

commits="(working tree)"
[[ -n "$range" ]] && commits="$(git -C "$REPO_ROOT" log --format='%h %s' "$range" 2>/dev/null || true)"

LOG_FILE="$LOG_DIR/review-$RUN_ID.md"
log "reviewing $diff_desc with $REVIEW_MODEL"

prompt="$(cat "$PROMPTS_DIR/review.md")
<coding_standards>
$standards
</coding_standards>

<commits>
$commits
</commits>

<diff>
$diff
</diff>"

set +e
printf '%s' "$prompt" | run_agent "$REVIEW_MODEL" 2>&1 | tee "$LOG_FILE"
status=${PIPESTATUS[1]}
set -e

(( status == 0 )) || die "reviewer exited $status — see $LOG_FILE"

log "review saved to $LOG_FILE"
