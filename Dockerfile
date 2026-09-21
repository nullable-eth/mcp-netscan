# syntax=docker/dockerfile:1

# --- tools stage -------------------------------------------------------------
# nuclei (pinned to the latest release, checksum-verified) and its templates
# (cloned at build time, so the running pod never fetches templates over its
# egress), plus kubectl for the exit-controller command mode. Built on slim so
# this stage stays quick and cache-friendly.
FROM debian:bookworm-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl unzip git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
           | grep -Po '"tag_name":\s*"v\K[^"]+')"; \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${ver}"; \
    zip="nuclei_${ver}_linux_amd64.zip"; \
    curl -fsSL -o "/tmp/${zip}" "${base}/${zip}"; \
    curl -fsSL -o /tmp/sums.txt "${base}/nuclei_${ver}_checksums.txt"; \
    (cd /tmp && grep "${zip}" sums.txt | sha256sum -c -); \
    unzip -o "/tmp/${zip}" nuclei -d /usr/local/bin; \
    /usr/local/bin/nuclei -version
RUN set -eux; \
    kver="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"; \
    curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${kver}/bin/linux/amd64/kubectl"; \
    curl -fsSL -o /tmp/kubectl.sha256 "https://dl.k8s.io/release/${kver}/bin/linux/amd64/kubectl.sha256"; \
    echo "$(cat /tmp/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c -; \
    chmod +x /usr/local/bin/kubectl
RUN git clone --depth 1 \
      https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
 && rm -rf /opt/nuclei-templates/.git \
 && chmod -R a+rX /opt/nuclei-templates

# --- runtime image -----------------------------------------------------------
# Official Kali + the "large" tool metapackage: every Kali recon AND
# exploitation tool is present when an operator execs into the pod. Kali
# maintains that tool list, so this Dockerfile stays a thin layer with nothing
# to hand-curate. Which of these the AGENT may drive is a separate, code-level
# allow-list (netscan/arsenal.py) enforced by run_tool; the rest are here for
# manual `kubectl exec` use only.
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      kali-linux-large wireguard-tools python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Our MCP server's Python deps live in their own venv, isolated from Kali's
# system Python (which many of the tools themselves use).
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
COPY netscan/ /srv/netscan/
WORKDIR /srv
ENV PATH=/opt/venv/bin:$PATH HOME=/tmp PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080

# Runs as root: raw-socket recon (masscan, nmap -sS, arp-scan) needs it, and the
# pod is already strongly contained — fail-closed WireGuard egress, no cluster
# credentials, one scan at a time, argv-only exec. The scanner Deployment
# tightens this with a securityContext (cap drop-all but NET_RAW, no privilege
# escalation); the exit-controller Deployment overrides USER to non-root 65534
# and command to ["python","-m","netscan.exit_controller"].
CMD ["python", "-m", "netscan.server"]
