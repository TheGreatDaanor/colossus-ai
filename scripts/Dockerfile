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
# -------------------------------------------------------------------------------

# Non-root, with a uid that maps cleanly onto a Linux host bind mount.
ARG UID=1001
ARG GID=1001
RUN groupadd -g "$GID" agent 2>/dev/null || true \
 && useradd -m -u "$UID" -g "$GID" agent 2>/dev/null || true

WORKDIR /repo
RUN git config --system --add safe.directory /repo

ENV AFK_SANDBOXED=1
USER agent
CMD ["bash"]
