# Disposable detonation image: Node (to run MCP servers) + Python (Warden) +
# tcpdump (to capture DNS at the container boundary — app-agnostic, so it sees
# where a server phones home even when it ignores HTTP_PROXY, which Node does).
# The CONTAINER is the isolation boundary.
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Warden itself (source; run via `python3 -m warden`, no pip needed).
COPY warden /opt/warden/warden
COPY pyproject.toml README.md /opt/warden/
ENV PYTHONPATH=/opt/warden
ENV WARDEN_HOME=/tmp/warden

# An unprivileged user to actually RUN the untrusted server (tcpdump stays root).
RUN useradd -m detonator
