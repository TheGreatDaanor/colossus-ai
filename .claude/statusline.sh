#!/usr/bin/env bash
#
# Statusline: live token count against the smart zone.
#
# You cannot manage context you cannot see. This reads the session transcript and
# reports the real total — input + both cache buckets + output — because that is
# what the attention mechanism is actually working over.
#
# Thresholds:  green < 100k (smart)  |  amber < 160k (degrading)  |  red (dumb zone)
# When it goes amber, finish the thought and clear. Do not compact.

set -uo pipefail

input="$(cat)"

j() { printf '%s' "$input" | jq -r "$1" 2>/dev/null; }

model="$(j '.model.display_name // "?"')"
cwd="$(j '.workspace.current_dir // .cwd // ""')"
transcript="$(j '.transcript_path // ""')"

dir="${cwd##*/}"
[[ -z "$dir" ]] && dir="?"

branch=""
if [[ -n "$cwd" ]] && command -v git >/dev/null 2>&1; then
  branch="$(git -C "$cwd" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
fi

# Last assistant message carries the cumulative context for the session.
tokens=0
if [[ -f "$transcript" ]] && command -v jq >/dev/null 2>&1; then
  tokens="$(jq -s '
      [ .[]
        | select(.message.usage != null)
        | .message.usage
        | ( (.input_tokens              // 0)
          + (.cache_read_input_tokens   // 0)
          + (.cache_creation_input_tokens // 0)
          + (.output_tokens             // 0) )
      ] | last // 0
    ' "$transcript" 2>/dev/null || echo 0)"
fi
[[ "$tokens" =~ ^[0-9]+$ ]] || tokens=0

SMART_LIMIT="${SMART_ZONE_LIMIT:-100000}"
WARN_LIMIT="${DUMB_ZONE_LIMIT:-160000}"

if   (( tokens < SMART_LIMIT )); then colour='32'; zone='smart'
elif (( tokens < WARN_LIMIT  )); then colour='33'; zone='fading'
else                                  colour='31'; zone='DUMB — clear now'
fi

if   (( tokens >= 1000 )); then pretty="$(( tokens / 1000 ))k"
else                            pretty="$tokens"
fi

printf '\033[2m%s\033[0m' "$dir"
[[ -n "$branch" ]] && printf '\033[2m:%s\033[0m' "$branch"
printf '  \033[2m%s\033[0m' "$model"
printf '  \033[%sm%s (%s)\033[0m' "$colour" "$pretty" "$zone"
