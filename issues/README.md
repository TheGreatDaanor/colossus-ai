# issues/

The kanban board. One markdown file per issue, named `NNN-slug.md`.

Files starting with `_` and this README are ignored by the scripts.

## Frontmatter contract

The scripts parse these four fields. Get them wrong and the loop misbehaves.

```yaml
---
id: 003              # zero-padded, matches the filename prefix
title: ...           # one line
status: open         # open | done
type: afk            # afk | human
blocked-by: [001, 002]   # ids that must be `status: done` first
---
```

- **`status: open`** → eligible. Set to `done` when merged, don't delete the file
  until the whole PRD ships (the loop uses `done` to resolve blockers).
- **`type: afk`** → the loop will pick it up unattended. **`type: human`** → the loop
  skips it; it needs your eyes (anything front-end-visual, anything with a
  judgement call, anything touching auth or payments).
- **`blocked-by: []`** → unblocked, grabbable now. This is what makes the board a
  DAG instead of a phase list, and it's what `parallel.sh` reads to decide how many
  agents to launch.

## Cutting good issues

Every issue is a **tracer bullet**: it crosses schema → service → visible surface,
so it ends in feedback. An issue that only touches the schema is a horizontal slice
— it produces no signal until two more issues land, and by then the agent has been
coding blind for three iterations.

The tell: if the "Definition of done" has no line a human can click or curl, re-cut it.

## Lifecycle

1. `prd-to-issues` generates them.
2. `loop.sh` / `parallel.sh` implement them and flip `status: done`.
3. QA generates *new* issues here while implementation is still running.
4. When the PRD ships, delete the PRD and the closed issues. Stale specs actively
   mislead future agents.
