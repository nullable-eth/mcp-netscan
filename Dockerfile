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
RUN git clone --depth 1 \
      https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
 && rm -rf /opt/nuclei-templates/.git \
 && chmod -R a+rX /opt/nuclei-templates

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap sslscan ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /install /usr/local
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
COPY netscan/ /srv/netscan/
WORKDIR /srv
# HOME must be writable for nuclei's runtime cache; the templates are read-only.
ENV HOME=/tmp PORT=8080 PYTHONUNBUFFERED=1
USER 65534
EXPOSE 8080
CMD ["python", "-m", "netscan.server"]
