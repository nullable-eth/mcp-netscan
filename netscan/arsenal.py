"""The Kali arsenal exposed to the agent through one generic exec tool.

run_tool(tool, args) runs a single allow-listed binary as a fixed argv (never a
shell), so the agent drives the recon/assessment tools with their native flags
— as if they were on its own PATH — with no bespoke MCP wrapper per tool.

The allow-list below IS the security boundary and it is default-deny: a binary
the agent may run is listed in ALLOWED; everything else Kali installs (the
exploitation frameworks and credential-attack tools) is present for a human
operating the pod by hand and is refused to the agent.

  MAY run (here): port/host discovery, service/version detection, DNS/subdomain
  /OSINT enumeration, web and TLS assessment, and vulnerability *detection* —
  including sqlmap and nmap's full NSE, which reveal whether a weakness is
  exploitable without an operator driving a framework.

  MAY NOT run (absent from ALLOWED, manual `kubectl exec` only): Metasploit
  (msfconsole/msfvenom/msfdb), stand-alone credential attacks (hydra, medusa,
  ncrack, patator, crackmapexec/netexec, responder), offline crackers (john,
  hashcat), and interception/C2 tooling (ettercap, bettercap, beef).

Containment does not rest on this list alone: the pod egresses only through the
fail-closed WireGuard tunnel, holds no cluster credentials, and every run is
argv-only, serialised, output-capped and time-bounded (netscan.runner). The
standing rule holds: only scan hosts the operator owns or is authorised to test.
"""
from __future__ import annotations

import re

from . import runner

# A bare binary name: lowercase, starts alphanumeric, no path separators.
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

MAX_ARGS = 128
MAX_ARG_LEN = 4096
DEFAULT_TIMEOUT = 300.0
MAX_TIMEOUT = 900.0


class ToolError(ValueError):
    """A run_tool request was refused or could not run. Message is safe to return."""

# name -> (category, one-line description). This is the whole boundary; adding a
# tool here makes it agent-runnable, so add only recon/assessment/detection
# tools. A listed tool that is not installed simply returns "not found on PATH".
ALLOWED: dict[str, tuple[str, str]] = {
    # -- host / port discovery --
    "nmap":        ("discovery", "port/service/OS scan and full NSE scripting"),
    "masscan":     ("discovery", "internet-scale asynchronous TCP port sweep"),
    "naabu":       ("discovery", "fast SYN/CONNECT port scanner (ProjectDiscovery)"),
    "rustscan":    ("discovery", "fast port scanner that feeds open ports to nmap"),
    "fping":       ("discovery", "ICMP host-liveness sweep"),
    "arp-scan":    ("discovery", "layer-2 host discovery on the local segment"),
    "netdiscover": ("discovery", "ARP-based host discovery"),
    # -- DNS / subdomain / OSINT --
    "dig":         ("dns_osint", "DNS lookups"),
    "host":        ("dns_osint", "DNS lookups"),
    "nslookup":    ("dns_osint", "DNS lookups"),
    "dnsx":        ("dns_osint", "fast DNS resolver/toolkit (ProjectDiscovery)"),
    "dnsrecon":    ("dns_osint", "DNS enumeration and zone-transfer checks"),
    "dnsenum":     ("dns_osint", "DNS enumeration"),
    "fierce":      ("dns_osint", "DNS reconnaissance / subdomain scan"),
    "subfinder":   ("dns_osint", "passive subdomain enumeration"),
    "amass":       ("dns_osint", "subdomain enumeration and attack-surface mapping"),
    "assetfinder": ("dns_osint", "subdomain discovery"),
    "findomain":   ("dns_osint", "subdomain discovery"),
    "sublist3r":   ("dns_osint", "subdomain enumeration"),
    "theharvester":("dns_osint", "OSINT email/host/subdomain gathering"),
    "whois":       ("dns_osint", "registration/ownership lookup"),
    # -- web assessment --
    "httpx":       ("web", "fast HTTP prober and tech fingerprint (ProjectDiscovery)"),
    "whatweb":     ("web", "web technology fingerprinting"),
    "wafw00f":     ("web", "web application firewall detection"),
    "nikto":       ("web", "web server misconfiguration / known-issue scan"),
    "nuclei":      ("web", "templated vulnerability detection"),
    "gobuster":    ("web", "content/dir/vhost/DNS brute-forcing (discovery)"),
    "feroxbuster": ("web", "recursive content discovery"),
    "ffuf":        ("web", "web fuzzer for content/parameter discovery"),
    "dirb":        ("web", "web content brute-forcing"),
    "dirsearch":   ("web", "web path discovery"),
    "wpscan":      ("web", "WordPress enumeration and vulnerability detection"),
    "joomscan":    ("web", "Joomla enumeration"),
    "cmseek":      ("web", "CMS detection and enumeration"),
    "droopescan":  ("web", "CMS (Drupal/SilverStripe/...) enumeration"),
    "sqlmap":      ("web", "SQL-injection detection (default, non-exploit mode)"),
    "curl":        ("web", "fetch/inspect HTTP responses"),
    "wget":        ("web", "fetch HTTP resources"),
    # -- TLS --
    "sslscan":     ("tls", "TLS protocols, ciphers, cert and known flaws"),
    "sslyze":      ("tls", "TLS configuration analysis"),
    "testssl.sh":  ("tls", "TLS/SSL posture and known-flaw checks"),
    "openssl":     ("tls", "TLS handshakes and certificate inspection"),
    # -- SMB / network service enumeration --
    "enum4linux":    ("smb_net", "SMB/NetBIOS enumeration"),
    "enum4linux-ng": ("smb_net", "SMB/NetBIOS enumeration (rewrite)"),
    "smbmap":        ("smb_net", "SMB share enumeration"),
    "smbclient":     ("smb_net", "SMB client — list shares / null session"),
    "nbtscan":       ("smb_net", "NetBIOS name scan"),
    "rpcclient":     ("smb_net", "MSRPC enumeration"),
    "showmount":     ("smb_net", "NFS export listing"),
    "ldapsearch":    ("smb_net", "LDAP enumeration"),
    # -- SNMP --
    "onesixtyone":  ("snmp", "SNMP community-string sweep"),
    "snmpwalk":     ("snmp", "SNMP enumeration"),
    "snmpbulkwalk": ("snmp", "SNMP enumeration (bulk)"),
    "snmp-check":   ("snmp", "SNMP device enumeration"),
    # -- vulnerability info --
    "searchsploit": ("vuln", "offline Exploit-DB search (information only)"),
}


def list_arsenal() -> dict:
    """The tools the agent may run via run_tool, grouped by category, for
    discovery. Exploitation/credential tools are deliberately absent."""
    cats: dict[str, list[dict]] = {}
    for name, (cat, desc) in sorted(ALLOWED.items()):
        cats.setdefault(cat, []).append({"tool": name, "description": desc})
    return {
        "allowed": cats,
        "count": len(ALLOWED),
        "note": ("Run any of these with run_tool(tool, args), native flags. "
                 "Exploitation and credential-attack tools are installed on the "
                 "image but not agent-runnable — use `kubectl exec` for those."),
    }


async def run_tool(tool: str, args: list[str] | None = None, *,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Run one allow-listed binary as argv (no shell) and return its result.

    tool is a bare binary name that must be in ALLOWED; args is its argv tail,
    passed through untouched (argv-only, so no shell metacharacter can matter).
    """
    name = (tool or "").strip()
    if not _NAME.match(name):
        raise ToolError("tool must be a bare binary name (a-z 0-9 . _ -)")
    if name not in ALLOWED:
        raise ToolError(
            f"'{name}' is not on the agent allow-list; it may be installed for "
            f"manual operator use only (see run_tool / list_arsenal)")

    argv_tail = args if args is not None else []
    if not isinstance(argv_tail, list) or not all(isinstance(a, str) for a in argv_tail):
        raise ToolError("args must be a list of strings")
    if len(argv_tail) > MAX_ARGS:
        raise ToolError(f"too many arguments (max {MAX_ARGS})")
    for a in argv_tail:
        if len(a) > MAX_ARG_LEN:
            raise ToolError(f"an argument exceeds {MAX_ARG_LEN} characters")
        if "\x00" in a:
            raise ToolError("an argument contains a NUL byte")

    budget = max(1.0, min(float(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    argv = [name, *argv_tail]
    try:
        rc, out, err = await runner.run(argv, timeout=budget)
    except runner.ScanError as e:
        msg = str(e)
        if "time limit" in msg:  # timed out; return partial rather than error
            return {"tool": name, "argv": argv, "timed_out": True, "note": msg}
        raise ToolError(msg)
    return {"tool": name, "argv": argv, "returncode": rc,
            "stdout": out, "stderr": err, "timed_out": False}
