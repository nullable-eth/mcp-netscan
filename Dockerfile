FROM python:3.13-slim AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# nuclei binary (latest release, checksum-verified) and its templates (pinned to
# a shallow clone at build time, so the running pod never fetches templates over
# its open egress).
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
# kubectl (checksum-verified) — used only by the exit-controller role.
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

FROM python:3.13-slim
# nmap/sslscan for the scanner; wireguard-tools (wg keygen) for the controller.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap sslscan wireguard-tools ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /install /usr/local
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
COPY netscan/ /srv/netscan/
WORKDIR /srv
# HOME must be writable for nuclei's runtime cache; the templates are read-only.
ENV HOME=/tmp PORT=8080 PYTHONUNBUFFERED=1
USER 65534
EXPOSE 8080
# Default = the MCP scanner server. The exit-controller Deployment overrides
# command with: ["python","-m","netscan.exit_controller"].
CMD ["python", "-m", "netscan.server"]
