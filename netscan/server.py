"""The MCP server. Exposes the scans as tools over streamable HTTP at /mcp, the
transport agentgateway connects to. Tool docstrings are what the model sees, so
they state both what the tool does and the standing rule: only scan hosts the
operator owns or is authorised to test.
"""
from __future__ import annotations

import json
import logging
import os

from mcp.server.fastmcp import FastMCP

from . import tools
from .runner import ScanError
from .validate import TargetError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netscan")

mcp = FastMCP(
    "netscan",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
    streamable_http_path="/mcp",
)


async def _call(kind: str, coro):
    try:
        return json.dumps(await coro, default=str)
    except (TargetError, ScanError) as e:
        return json.dumps({"error": str(e)})
    except Exception as e:  # never leak a traceback to the model
        log.exception("%s failed", kind)
        return json.dumps({"error": f"{kind} failed: {type(e).__name__}"})


@mcp.tool()
async def port_scan(target: str, ports: str = "", top_ports: int = 100,
                    service_detection: bool = True, timing: str = "normal",
                    max_rate: int = 300, allow_large: bool = False) -> str:
    """Scan a host for open TCP ports and identify the services on them (nmap
    connect scan). target is one IP, hostname, or CIDR (<=256 hosts, or 4096
    with allow_large). ports is an nmap spec like '22,80,443' or '1-1024';
    leave empty to scan the top top_ports. timing is polite|normal|aggressive.
    max_rate caps packets/sec (hard cap 1000). Detection only. Only scan hosts
    you own or are explicitly authorised to test.
    """
    return await _call("port_scan", tools.port_scan(
        target, ports=ports, top_ports=top_ports,
        service_detection=service_detection, timing=timing,
        max_rate=max_rate, allow_large=allow_large))


@mcp.tool()
async def vuln_scan(target: str, ports: str = "", top_ports: int = 100,
                    max_rate: int = 300) -> str:
    """Detect known vulnerabilities on a host's services using nmap's NSE 'vuln'
    scripts plus version detection. Denial-of-service, exploit, and brute-force
    scripts are excluded: this reports weaknesses, it does not exploit them.
    Slower than port_scan. Same target/ports arguments. Only scan hosts you own
    or are explicitly authorised to test.
    """
    return await _call("vuln_scan", tools.vuln_scan(
        target, ports=ports, top_ports=top_ports, max_rate=max_rate))


@mcp.tool()
async def web_scan(url: str, severity: str = "", rate: int = 150,
                   concurrency: int = 25) -> str:
    """Scan one web endpoint for known vulnerabilities and misconfigurations
    with nuclei's bundled templates (exposed panels, default-credential
    detection, CVEs, security-header gaps, ...). url is an http(s) URL or a bare
    host (defaults to https). severity optionally filters, e.g. 'high,critical'.
    Out-of-band probing is off and denial-of-service templates are excluded.
    Only scan hosts you own or are explicitly authorised to test.
    """
    return await _call("web_scan", tools.web_scan(
        url, severity=severity, rate=rate, concurrency=concurrency))


@mcp.tool()
async def tls_scan(target: str, port: int = 443) -> str:
    """Inspect a host's TLS: supported protocol versions, cipher suites, the
    certificate (issuer, validity, signature algorithm), and protocol flaws
    such as Heartbleed (sslscan). target is one IP or hostname. Only scan hosts
    you own or are explicitly authorised to test.
    """
    return await _call("tls_scan", tools.tls_scan(target, port=port))


def main() -> None:
    log.info("netscan MCP server starting on %s:%s/mcp",
             mcp.settings.host, mcp.settings.port)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
