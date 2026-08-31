# Disposable detonation image: Node (to run MCP servers) + Python (Driftward) +
# tcpdump (to capture DNS at the container boundary — app-agnostic, so it sees
# where a server phones home even when it ignores HTTP_PROXY, which Node does).
# The CONTAINER is the isolation boundary.
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Driftward itself (source; run via `python3 -m driftward`, no pip needed).
COPY driftward /opt/driftward/driftward
COPY pyproject.toml README.md /opt/driftward/
ENV PYTHONPATH=/opt/driftward
ENV DRIFTWARD_HOME=/tmp/driftward

# An unprivileged user to actually RUN the untrusted server (tcpdump stays root).
RUN useradd -m detonator
