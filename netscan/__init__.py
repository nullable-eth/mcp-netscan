"""mcp-netscan — a network reconnaissance and vulnerability-scanning MCP server
for the Whitehorse cluster agent.

It wraps mainstream, non-exploitative audit tools (nmap, nuclei, sslscan) behind
the Model Context Protocol. It performs detection, never exploitation: no brute
force, no denial of service, no exploit delivery. Those tool categories are
compiled out here, not merely discouraged.

Targets are NOT restricted to an allowlist — the operator asked for arbitrary
targets, gated instead by the API key in front of the gateway. What IS enforced,
for every caller, is operational safety that any competent scanner has
regardless of target: strict argument construction (no shell, no argv
injection), per-scan timeouts, transmit-rate caps so a scan cannot flood a host
or trip a WAN alarm, a cap on how large a CIDR may be swept at once, and a
single-heavy-scan lock.
"""
