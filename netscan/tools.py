"""The scans themselves: nmap (ports and NSE vuln detection), nuclei (templated
web vulnerability detection), and sslscan (TLS posture). Each builds a fixed
argv from already-validated inputs, runs it through the bounded runner, and
returns a structured result. Nothing here exploits, brute-forces, or floods:
those nmap script categories and nuclei tags are excluded by construction, and
every scan carries a transmit-rate cap and a timeout.
"""
from __future__ import annotations

import os
import pathlib
import xml.etree.ElementTree as ET

from . import runner, validate

# Hard ceilings. Callers may ask for less, never more.
MAX_RATE_HARD = 1000          # packets/sec for nmap
NUCLEI_RATE_HARD = 300        # requests/sec for nuclei
TIMING = {"polite": "-T2", "normal": "-T3", "aggressive": "-T4"}
NUCLEI_TEMPLATES = "/opt/nuclei-templates"


def _rate(requested: int, default: int, hard: int) -> str:
    r = default if not requested else int(requested)
    return str(max(1, min(r, hard)))


async def port_scan(target: str, *, ports: str = "", top_ports: int = 100,
                    service_detection: bool = True, timing: str = "normal",
                    max_rate: int = 300, allow_large: bool = False,
                    timeout: float = 180.0) -> dict:
    """TCP connect scan (-sT, no privilege needed). Host discovery is skipped
    (-Pn) because many hosts drop ping."""
    tgt = validate.normalize_target(target, allow_large=allow_large)
    argv = ["nmap", "-sT", "-Pn", "-n", "--max-rate",
            _rate(max_rate, 300, MAX_RATE_HARD), TIMING.get(timing, "-T3")]
    p = validate.normalize_ports(ports)
    if p:
        argv += ["-p", p]
    else:
        argv += ["--top-ports", str(max(1, min(int(top_ports), 65535)))]
    if service_detection:
        argv += ["-sV", "--version-intensity", "5"]
    argv += ["-oX", "-", tgt]
    rc, out, err = await runner.run(argv, timeout=min(timeout, 900.0))
    result = _parse_nmap(out)
    result["target"] = tgt
    if not result["hosts"] and err:
        result["error"] = err.strip()[:500]
    return result


async def vuln_scan(target: str, *, ports: str = "", top_ports: int = 100,
                    max_rate: int = 300, timeout: float = 300.0) -> dict:
    """Two-phase, hard-bounded NSE 'vuln' detection (denial-of-service, exploit
    and brute-force scripts excluded; detection only).

    Phase 1 finds the open ports quickly; phase 2 runs -sV plus the vuln scripts
    ONLY on those, under an nmap --host-timeout. The NSE vuln scripts (HTTP
    enumeration especially) are slow, so without this a scan runs for many
    minutes and overruns the caller's tool-call timeout. Bounded, it always
    returns within the budget with whatever it found (partial when it ran long).
    """
    tgt = validate.normalize_target(target)
    budget = min(float(timeout), 900.0)
    rate = _rate(max_rate, 300, MAX_RATE_HARD)
    p = validate.normalize_ports(ports)
    portsel = ["-p", p] if p else ["--top-ports", str(max(1, min(int(top_ports), 65535)))]

    # Phase 1: quick open-port discovery (seconds).
    disc = ["nmap", "-sT", "-Pn", "-n", "--max-rate", rate, "-T4",
            *portsel, "-oX", "-", tgt]
    rc, out, err = await runner.run(disc, timeout=min(budget, 60.0))
    discovered = _parse_nmap(out)
    open_ports = sorted({pt["port"] for h in discovered["hosts"]
                         for pt in h["ports"] if pt.get("state") == "open"})
    if not open_ports:
        discovered["target"] = tgt
        discovered["note"] = "no open TCP ports found; nothing to vuln-scan"
        if not discovered["hosts"] and err:
            discovered["error"] = err.strip()[:500]
        return discovered

    # Phase 2: version + vuln scripts on the open ports only, hard-bounded so a
    # slow script set cannot overrun the caller. nmap returns what it completed
    # before the host-timeout fires.
    host_to = max(60, int(budget * 0.9))
    argv = ["nmap", "-sT", "-Pn", "-n", "-sV", "--version-intensity", "5",
            "--max-rate", rate,
            "--script", "vuln and not (dos or exploit or brute)",
            "--script-timeout", "60s", "--host-timeout", f"{host_to}s",
            "-p", ",".join(str(x) for x in open_ports), "-oX", "-", tgt]
    rc, out, err = await runner.run(argv, timeout=min(budget, 900.0))
    result = _parse_nmap(out)
    result["target"] = tgt
    result["open_ports_scanned"] = open_ports
    if not result["hosts"] and err:
        result["error"] = err.strip()[:500]
    return result


async def web_scan(url: str, *, severity: str = "", rate: int = 150,
                   concurrency: int = 25, timeout: float = 480.0) -> dict:
    """nuclei against one http(s) target with the bundled templates. The
    denial-of-service tag is excluded and out-of-band (interactsh) probing is
    off, so no traffic leaves toward a third-party OOB server. Findings are
    written to a file as they are found, so if the run hits its timeout the
    partial results are still returned instead of an error."""
    safe_url, host = validate.normalize_url(url)
    out_path = f"/tmp/nuclei-{os.getpid()}.jsonl"
    try:
        pathlib.Path(out_path).unlink()
    except OSError:
        pass
    argv = ["nuclei", "-u", safe_url, "-jsonl", "-o", out_path, "-silent",
            "-disable-update-check", "-no-interactsh", "-templates", NUCLEI_TEMPLATES,
            "-rl", _rate(rate, 150, NUCLEI_RATE_HARD),
            "-c", str(max(1, min(int(concurrency), 50))),
            "-timeout", "10", "-retries", "1", "-etags", "dos"]
    sev = str(severity or "").strip().lower()
    allowed = {"info", "low", "medium", "high", "critical"}
    if sev:
        wanted = ",".join(s for s in sev.split(",") if s in allowed)
        if wanted:
            argv += ["-severity", wanted]
    partial, err = False, ""
    try:
        rc, out, err = await runner.run(argv, timeout=min(float(timeout), 900.0))
    except runner.ScanError:
        partial = True   # timed out; whatever nuclei wrote so far is still useful
    try:
        text = pathlib.Path(out_path).read_text()
    except OSError:
        text = ""
    findings = _parse_nuclei(text)
    res = {"url": safe_url, "host": host, "findings": findings,
           "finding_count": len(findings), "partial": partial}
    if not findings and err.strip():
        res["stderr"] = err.strip()[:500]
    return res


async def tls_scan(target: str, *, port: int = 443, timeout: float = 120.0) -> dict:
    """sslscan: protocols, cipher suites, certificate, and the handful of
    protocol flaws (e.g. Heartbleed) it probes for."""
    tgt = validate.normalize_target(target, allow_cidr=False)
    port = int(port)
    if not 0 < port <= 65535:
        raise validate.TargetError("port out of range")
    argv = ["sslscan", "--no-colour", "--xml=-", f"{tgt}:{port}"]
    rc, out, err = await runner.run(argv, timeout=min(timeout, 300.0))
    res = _parse_sslscan(out)
    res.update(target=tgt, port=port)
    if not res.get("protocols") and err.strip():
        res["error"] = err.strip()[:500]
    return res


# ---------------------------------------------------------------- parsers

def _parse_nmap(xml: str) -> dict:
    out: dict = {"hosts": []}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        addr = next((a.get("addr") for a in host.findall("address")), None)
        st = host.find("status")
        h: dict = {"address": addr,
                   "state": st.get("state") if st is not None else None,
                   "ports": []}
        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            scripts = [{"id": s.get("id"), "output": (s.get("output") or "").strip()}
                       for s in port.findall("script")]
            h["ports"].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "scripts": scripts,
            })
        host_scripts = [{"id": s.get("id"), "output": (s.get("output") or "").strip()}
                        for s in host.findall("./hostscript/script")]
        if host_scripts:
            h["host_scripts"] = host_scripts
        out["hosts"].append(h)
    return out


def _parse_nuclei(text: str) -> list[dict]:
    import json
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info") or {}
        findings.append({
            "template": j.get("template-id") or j.get("templateID"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": j.get("matched-at") or j.get("matched"),
            "type": j.get("type"),
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get((f.get("severity") or "").lower(), 9))
    return findings


def _parse_sslscan(xml: str) -> dict:
    res: dict = {"protocols": [], "ciphers": [], "certificate": {},
                 "vulnerabilities": {}}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return res
    test = root.find("ssltest")
    if test is None:
        return res
    for proto in test.findall("protocol"):
        if proto.get("enabled") == "1":
            res["protocols"].append(f"{proto.get('type')} {proto.get('version')}")
    for c in test.findall("cipher"):
        res["ciphers"].append({
            "protocol": c.get("sslversion"), "bits": c.get("bits"),
            "cipher": c.get("cipher"), "strength": c.get("strength"),
        })
    for tag in ("heartbleed",):
        for hb in test.findall(tag):
            if hb.get("vulnerable") == "1":
                res["vulnerabilities"].setdefault(tag, []).append(
                    hb.get("sslversion"))
    cert = test.find("certificate")
    if cert is None:
        cert = test.find("certificates/certificate")
    if cert is not None:
        res["certificate"] = {
            "subject": _celltext(cert, "subject"),
            "issuer": _celltext(cert, "issuer"),
            "not_before": _celltext(cert, "not-valid-before"),
            "not_after": _celltext(cert, "not-valid-after"),
            "signature_algorithm": _celltext(cert, "signature-algorithm"),
        }
    return res


def _celltext(parent, tag):
    el = parent.find(tag)
    return (el.text or "").strip() if el is not None and el.text else None
