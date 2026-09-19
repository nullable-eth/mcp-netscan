"""Turn caller-supplied strings into arguments that are safe to hand to a
scanner as a single argv element. The rule we never break: a value must not be
able to become a flag or a shell token. Everything is matched against a strict
shape and rejected otherwise, so an injected script argument, a shell
metacharacter, a command substitution, or a leading hyphen can never reach nmap
or nuclei.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# A DNS hostname label: letters/digits/hyphen, not starting/ending with hyphen.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
# nmap port spec: 22  80,443  1-1024  (no protocol prefixes, no scripts).
_PORTS = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")

# Characters that must never appear in a target: whitespace and shell/argv
# metacharacters. Kept as an explicit set so the intent is auditable.
_FORBIDDEN = set(" \t\r\n;|&$`\\<>(){}[]!*?'\"")

# Largest CIDR a single call may sweep. /24 (256) is routine; a wider sweep is
# either a mistake or an internet scan, so it needs allow_large, and even then
# there is a hard ceiling.
MAX_CIDR_HOSTS_DEFAULT = 256
MAX_CIDR_HOSTS_HARD = 4096


class TargetError(ValueError):
    """The target could not be accepted. The message is safe to return."""


def normalize_target(target: str, *, allow_cidr: bool = True,
                     allow_large: bool = False) -> str:
    """Return a single argv-safe target (host, IP, or CIDR) or raise TargetError.

    Accepts one IPv4/IPv6 address, one IP network in CIDR form, or one DNS
    hostname. Rejects everything else, including any value beginning with a
    hyphen or containing whitespace or a shell metacharacter.
    """
    if not isinstance(target, str):
        raise TargetError("target must be a string")
    t = target.strip()
    if not t or len(t) > 255:
        raise TargetError("target is empty or too long")
    if t[0] == "-":
        raise TargetError("target may not begin with a hyphen")
    if any(c in _FORBIDDEN for c in t):
        raise TargetError("target contains a disallowed character")

    if "/" in t:
        if not allow_cidr:
            raise TargetError("a CIDR range is not allowed for this scan")
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise TargetError("not a valid CIDR network")
        cap = MAX_CIDR_HOSTS_HARD if allow_large else MAX_CIDR_HOSTS_DEFAULT
        if net.num_addresses > cap:
            hint = ("reduce the range" if allow_large
                    else f"set allow_large for up to {MAX_CIDR_HOSTS_HARD}")
            raise TargetError(
                f"CIDR too large: {net.num_addresses} addresses > {cap}; {hint}")
        return str(net)

    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass

    if _HOSTNAME.match(t):
        return t.rstrip(".")
    raise TargetError("not a valid IP address, CIDR network, or hostname")


def normalize_ports(ports: str) -> str:
    """Return a validated nmap port spec, or '' when none was given."""
    if not ports:
        return ""
    p = ports.strip()
    if not _PORTS.match(p):
        raise TargetError("ports must look like '22', '80,443' or '1-1024'")
    for part in p.split(","):
        for n in part.split("-"):
            if not 0 < int(n) <= 65535:
                raise TargetError(f"port out of range: {n}")
    return p


def normalize_url(url: str) -> tuple[str, str]:
    """For web scans: accept an http(s) URL or a bare host, validate the host,
    and return (normalized_url, host). A bare host defaults to https.
    """
    u = (url or "").strip()
    if not u:
        raise TargetError("url is empty")
    if "://" not in u:
        u = "https://" + u
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https"):
        raise TargetError("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise TargetError("credentials in the URL are not allowed")
    host = parts.hostname or ""
    normalize_target(host, allow_cidr=False)  # validates the host, ignores result
    if parts.port is not None and not 0 < parts.port <= 65535:
        raise TargetError("port out of range")
    safe = f"{parts.scheme}://{parts.netloc}{parts.path or ''}"
    if parts.query:
        safe += "?" + parts.query
    return safe, host
