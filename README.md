# mcp-netscan

A network reconnaissance and vulnerability-scanning MCP server for the Whitehorse
cluster agent. It wraps mainstream, non-exploitative audit tools behind the Model
Context Protocol and serves them over streamable HTTP at `/mcp`.

## Tools

| tool | wraps | does |
|---|---|---|
| `port_scan` | nmap `-sT` | open TCP ports + service/version detection |
| `vuln_scan` | nmap NSE `vuln` | known-vulnerability detection (no dos/exploit/brute) |
| `web_scan` | nuclei | templated web vuln/misconfig detection (no dos, no OOB) |
| `tls_scan` | sslscan | TLS protocols, ciphers, certificate, protocol flaws |

## Boundaries

**Detection, never exploitation.** Brute force, denial of service, and exploit
delivery are excluded by construction — the dangerous nmap script categories and
nuclei tags are filtered in `tools.py`, not left to prompt discipline.

**Any target, gated by the key in front of the gateway.** There is no target
allowlist by design; access control is the API key on the gateway. Every scan
still enforces, for every caller, safety that does not depend on the target:

- **No shell, no argv injection.** Every caller-supplied value is matched against
  a strict shape (`validate.py`) before it can become an argv element; a value
  that could be a flag, a shell token, or a leading `-` is rejected.
- **Rate caps.** nmap `--max-rate` (hard cap 1000 pps) and nuclei `-rl` (hard cap
  300 rps) so a scan cannot flood a host or trip a WAN-egress alarm.
- **Timeouts** on every scan, killing the process group on expiry.
- **CIDR ceiling.** A single call sweeps at most /24 (256 hosts), or 4096 with
  `allow_large`; never more.
- **One heavy scan at a time**, so a burst of tool calls cannot fan out.

The tool docstrings, which the model sees, carry the standing instruction to
scan only hosts the operator owns or is authorised to test.

## Run

```
pip install -r requirements.txt && python -m netscan.server   # needs nmap/nuclei/sslscan on PATH
python -m pytest -q tests                                      # unit tests, no network
```

The container (`Dockerfile`) bundles nmap, sslscan, nuclei and its templates, and
runs as a non-root user with unprivileged connect scans (no `NET_RAW`).
