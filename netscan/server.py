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

from . import arsenal, tools
from .arsenal import ToolError
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
    except (TargetError, ScanError, ToolError) as e:
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


@mcp.tool()
async def list_arsenal() -> str:
    """List every command-line tool the agent may run through run_tool, grouped
    by category, with a one-line description each. Use this to discover what is
    available before calling run_tool. Exploitation frameworks and
    credential-attack tools are installed on the image but are NOT listed here
    and cannot be run by the agent (operator-only, via kubectl exec).
    """
    return await _call("list_arsenal", _wrap(arsenal.list_arsenal()))


@mcp.tool()
async def run_tool(tool: str, args: list[str] | None = None,
                   timeout: float = 300.0) -> str:
    """Run one allow-listed Kali recon/assessment tool with its NATIVE flags and
    return its raw output. This is the generic escape hatch: craft any invocation
    of an allowed tool as (tool, args) instead of looking for a bespoke wrapper.

    tool is a bare binary name that must be on the allow-list (see list_arsenal);
    args is its argument vector as a list of strings, e.g.
    run_tool("nmap", ["-sV", "--script", "http-title", "-p", "80,443", "10.0.0.5"]).
    Execution is argv-only (no shell is involved, so quoting/metacharacters are
    never interpreted), one tool at a time, with output capped and a timeout
    (default 300s, max 900s). returncode, stdout and stderr are returned as-is.

    Allowed: recon, enumeration, web/TLS assessment, and vulnerability detection
    (including sqlmap and nmap NSE). Not allowed: Metasploit, hydra/medusa/
    ncrack, john/hashcat, netexec, responder, ettercap/bettercap — these are
    present for manual operator use only. Only scan hosts you own or are
    explicitly authorised to test.
    """
    return await _call("run_tool", arsenal.run_tool(tool, args, timeout=timeout))


async def _wrap(value):
    """Adapt a plain (non-coroutine) result to the _call(await coro) contract."""
    return value


def main() -> None:
    log.info("netscan MCP server starting on %s:%s/mcp",
             mcp.settings.host, mcp.settings.port)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
