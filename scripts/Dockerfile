# Sandbox for unattended agent runs.
#
# The loop runs with permissions pre-accepted. That is only safe because it happens
# in here, with no access to anything outside the mounted repo.
#
# Add your project's toolchain at the marked line — the agent needs to actually run
# your tests, and a sandbox where the feedback loop fails is worse than no sandbox.

FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PNPM_HOME=/usr/local/pnpm \
    PATH=/usr/local/pnpm:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl jq ripgrep less \
      python3 python3-venv build-essential \
    && rm -rf /var/lib/apt/lists/*

# uv — fast Python installs matter inside a loop, where the agent reinstalls often
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Agent CLI
RUN npm install -g @anthropic-ai/claude-code

# ---- project toolchain: add anything your test/typecheck/lint commands need ----
RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apt-get update && apt-get install -y --no-install-recommends \
      postgresql-client libpq-dev \
    && rm -rf /var/lib/apt/lists/*
RUN uv venv /opt/venv && . /opt/venv/bin/activate
RUN apt-get update && apt-get install -y --no-install-recommends golang-go && rm -rf /var/lib/apt/lists/*
# -------------------------------------------------------------------------------

# Non-root, with a uid that maps cleanly onto a Linux host bind mount, so files
# the agent creates are owned by you and not by root.
#
# The awkward part: this base image already ships a user `node` at uid/gid 1000,
# which is also the first uid on most Linux desktops. So groupadd/useradd will
# collide for the majority of users. Handle it explicitly rather than papering
# over it — an earlier version used `|| true` here, the adds failed silently, and
# the build "succeeded" with no such user, producing this at run time:
#
#     docker: Error response from daemon: unable to find user agent:
#     no matching entries in passwd file
#
# set -eux means a real failure now fails the build, where you can see it.
#   - reuse the gid/uid if the base image already has one (do not fight it)
#   - otherwise create `agent`
#   - always own /home/agent: npm, git and the agent CLI write there, and
#     without it they fail in ways that are hard to trace back to here
ARG UID=1001
ARG GID=1001
RUN set -eux; \
    if ! getent group "$GID" >/dev/null; then groupadd -g "$GID" agent; fi; \
    if ! getent passwd "$UID" >/dev/null; then useradd -u "$UID" -g "$GID" -M -s /bin/bash agent; fi; \
    mkdir -p /home/agent/.cache /home/agent/.config; \
    chown -R "$UID:$GID" /home/agent; \
    echo "container user resolved to uid=$UID gid=$GID ($(getent passwd "$UID" | cut -d: -f1))"

ENV HOME=/home/agent

WORKDIR /repo
RUN git config --system --add safe.directory /repo

ENV AFK_SANDBOXED=1

# Numeric, not a name. Valid whether the uid belongs to `agent`, to the base
# image's `node`, or to nothing at all.
USER ${UID}:${GID}
CMD ["bash"]
