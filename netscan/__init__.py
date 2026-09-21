"""mcp-netscan — a network reconnaissance and vulnerability-assessment MCP
server for the Whitehorse cluster agent, on a Kali Linux base.

Two ways in. The structured tools (port_scan, vuln_scan, web_scan, tls_scan)
wrap nmap/nuclei/sslscan and return parsed JSON; they stay detection-only (no
brute, dos or exploit categories). The generic tool, run_tool, runs any binary
on a code-level allow-list (netscan/arsenal.py) with its native flags, so the
agent can drive the recon/assessment arsenal — including sqlmap and nmap's full
NSE — as if the tools were on its own PATH, without a bespoke wrapper each.

The allow-list is the boundary and it is default-deny. Kali installs a large
tool set (the exploitation frameworks and credential-attack tools among them);
those are present for a human operating the pod by hand and are NOT agent-
runnable. Adding a tool to arsenal.ALLOWED is what makes it agent-runnable.

Targets are NOT restricted to an allowlist — the operator asked for arbitrary
targets, gated instead by the API key in front of the gateway. What IS enforced,
for every caller, is operational safety any competent scanner has regardless of
target: strict argument construction (no shell, no argv injection), per-run
timeouts, transmit-rate caps on the structured scans, a cap on how large a CIDR
may be swept, a single-heavy-run lock, and a bound on captured output. Egress is
fail-closed through the WireGuard exit box and the pod holds no cluster creds.
"""
