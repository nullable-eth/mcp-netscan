"""Ephemeral Vultr WireGuard exit-box controller.

Runs as a Deployment scaled 0/1. Scale to 1 = provision a box and bring the
scanner's tunnel up; scale to 0 (SIGTERM) = tear the box down. The box exists
only while this pod runs, so `kubectl scale ... --replicas=1|0` is the on/off
switch (no cloud credential ever touches the credential-less scanner).

Config via env (see the Deployment):
  SCANNER_PUB     scanner WireGuard public key (public; safe in a ConfigMap)
  REGIONS         space-separated Vultr region codes to rotate through
  PLAN, OS_ID     Vultr plan / OS ids
  FW_GROUP        name of the FirewallGroup MR to attach
  NETSCAN_NS/DEPLOY/PEER_SECRET  where to write the peer + restart the scanner
  PROVIDER_CONFIG Crossplane ProviderConfig name (default: default)
Verification checks the scanner's real egress IP: after writing the peer secret
and restarting the scanner, we exec the netscan container and confirm its public
IP is the box IP. Pod-readiness is NOT a proxy — the gluetun killswitch keeps the
pod Ready even when the tunnel is down.
"""
import base64
import json
import os
import random
import signal
import subprocess
import sys
import time

SCANNER_PUB = os.environ["SCANNER_PUB"]
REGIONS = os.environ.get("REGIONS", "atl dfw ewr lax mia ord sea sjc").split()
PLAN = os.environ.get("PLAN", "vc2-1c-1gb")
OS_ID = int(os.environ.get("OS_ID", "2076"))  # Alpine Linux x64
FW_GROUP = os.environ.get("FW_GROUP", "netscan-exit")
NS = os.environ.get("NETSCAN_NS", "mcp")
DEPLOY = os.environ.get("NETSCAN_DEPLOY", "netscan-mcp")
PEER_SECRET = os.environ.get("PEER_SECRET", "netscan-wg-peer")
PROVIDER_CONFIG = os.environ.get("PROVIDER_CONFIG", "default")
NAME = "netscan-exit-box"  # the ephemeral Instance/StartupScript MR name
MAX_TRIES = int(os.environ.get("MAX_TRIES", "4"))
BILLING = "https://console.vultr.com/billing/"


def log(msg):
    print(f"[exit-controller] {msg}", flush=True)


def kubectl(args, stdin=None, check=True, retries=6):
    # At pod start the API can be briefly unreachable while the CNI programs this
    # pod's NetworkPolicy (seen as "dial 10.43.0.1:443: connection refused"),
    # which used to crash the controller on its first apply. Retry check=True
    # calls with a short backoff; check=False callers (pollers) handle their own.
    last = ""
    for _ in range(max(1, retries)):
        p = subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
        last = p.stderr.strip()
        if not check:
            return p.stdout.strip()
        time.sleep(3)
    raise RuntimeError(f"kubectl {' '.join(args)} failed after {retries} tries: {last}")


def wg_keypair():
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub


def render_startup(box_priv):
    # Alpine first-boot: install WG, bring up wg0, NAT to the default iface.
    # $DEV/$i are evaluated ON THE BOX at boot (single-quoted awk, escaped $).
    return f"""#!/bin/sh
exec >/var/log/wg-setup.log 2>&1
set -x
for i in $(seq 1 20); do getent hosts dl-cdn.alpinelinux.org && break; sleep 2; done
apk add wireguard-tools iptables iproute2
DEV=$(ip -o -4 route show to default | awk '{{print $5; exit}}')
mkdir -p /etc/wireguard
cat >/etc/wireguard/wg0.conf <<WG
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = {box_priv}
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING -o $DEV -j MASQUERADE; iptables -A FORWARD -i wg0 -o $DEV -j ACCEPT; iptables -A FORWARD -i $DEV -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
[Peer]
PublicKey = {SCANNER_PUB}
AllowedIPs = 10.9.0.2/32
WG
chmod 600 /etc/wireguard/wg0.conf
# Vultr base images (Alpine included) ship UFW with a default-DROP INPUT chain,
# which silently drops the inbound WireGuard handshake before it ever reaches
# wg0 — the box receives the packet at the NIC but never replies, so the tunnel
# never comes up. Open the listen port explicitly (the Vultr cloud firewall
# group already restricts inbound to UDP 51820, so this is not widening exposure).
iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT
wg-quick up wg0
"""


def apply(manifest):
    # --validate=false skips kubectl's openapi/v2 download (an extra API round
    # trip that was the first thing to fail at pod start); the apply itself still
    # goes through the API and is server-side validated.
    kubectl(["apply", "--validate=false", "-f", "-"], stdin=json.dumps(manifest))


def apply_box(region, box_priv):
    script_b64 = base64.b64encode(render_startup(box_priv).encode()).decode()
    apply({
        "apiVersion": "compute.vultr.upbound.io/v1beta1", "kind": "StartupScript",
        "metadata": {"name": NAME},
        "spec": {"forProvider": {"name": NAME, "type": "boot", "script": script_b64},
                 "providerConfigRef": {"name": PROVIDER_CONFIG}},
    })
    apply({
        "apiVersion": "compute.vultr.upbound.io/v1beta1", "kind": "Instance",
        "metadata": {"name": NAME},
        "spec": {"forProvider": {
            "region": region, "plan": PLAN, "osId": OS_ID,
            "label": NAME, "hostname": "netscan-exit",
            "scriptIdRef": {"name": NAME}, "firewallGroupIdRef": {"name": FW_GROUP},
        }, "providerConfigRef": {"name": PROVIDER_CONFIG}},
    })


def wait_for_ip(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ip = kubectl(["get", "instance.compute.vultr.upbound.io", NAME,
                      "-o", "jsonpath={.status.atProvider.mainIp}"], check=False)
        if ip:
            return ip
        time.sleep(5)
    return None


def set_peer(ip, box_pub):
    y = kubectl(["create", "secret", "generic", PEER_SECRET, "-n", NS,
                 f"--from-literal=WIREGUARD_ENDPOINT_IP={ip}",
                 f"--from-literal=WIREGUARD_PUBLIC_KEY={box_pub}",
                 "--dry-run=client", "-o", "yaml"])
    kubectl(["apply", "-f", "-"], stdin=y)


def restart_scanner():
    kubectl(["rollout", "restart", f"deploy/{DEPLOY}", "-n", NS])


def verify_tunnel(ip, timeout=120):
    # Confirm the scanner actually egresses through the box. Pod-readiness is NOT
    # a proxy any more: the gluetun killswitch keeps the pod Ready even with the
    # tunnel down, so check the scanner's real public IP == the box IP.
    deadline = time.time() + timeout
    while time.time() < deadline:
        pod = kubectl(["get", "pod", "-n", NS, "-l", f"app={DEPLOY}",
                       "--field-selector=status.phase=Running",
                       "-o", "jsonpath={.items[0].metadata.name}"], check=False)
        if pod:
            out = kubectl(["exec", "-n", NS, pod, "-c", "netscan", "--",
                           "curl", "-s", "--max-time", "10", "https://api.ipify.org"],
                          check=False)
            if out.strip() == ip:
                return True
        time.sleep(6)
    return False


def teardown():
    log("tearing down: deleting box + peer, scanner back to fail-closed")
    for kind in ("instance.compute.vultr.upbound.io", "startupscript.compute.vultr.upbound.io"):
        kubectl(["delete", kind, NAME, "--ignore-not-found", "--wait=false"], check=False)
    kubectl(["delete", "secret", PEER_SECRET, "-n", NS, "--ignore-not-found"], check=False)
    restart_scanner()


def bring_up():
    for attempt in range(1, MAX_TRIES + 1):
        region = random.choice(REGIONS)
        log(f"attempt {attempt}/{MAX_TRIES}: provisioning in {region}")
        box_priv, box_pub = wg_keypair()
        apply_box(region, box_priv)
        ip = wait_for_ip()
        if not ip:
            # No IP = provisioning failed. Overwhelmingly this is out-of-credit.
            log(f"PROVISION FAILED (no IP). Most likely the Vultr account is out "
                f"of credit — top up at {BILLING} — or Vultr is rate-limiting. "
                f"Tearing down and retrying.")
            teardown()
            continue
        log(f"box up at {ip}; wiring scanner and verifying tunnel")
        set_peer(ip, box_pub)
        restart_scanner()
        if verify_tunnel(ip):
            log(f"tunnel UP — scanner public IP is {ip} ({region}). Holding box up.")
            return True
        log("tunnel did not verify (scanner not egressing via the box) — reprovisioning")
        teardown()
    log(f"gave up after {MAX_TRIES} tries. If provisioning kept failing, check "
        f"Vultr credit: {BILLING}")
    return False


def main():
    stop = {"v": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("v", True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("v", True))
    if not bring_up():
        # Stay alive so the failure is visible (pod not crash-looping); operator
        # scales to 0 to clear. Teardown still runs on SIGTERM below.
        log("bring-up failed; idling until scaled to 0")
    try:
        while not stop["v"]:
            time.sleep(5)
    finally:
        teardown()
        log("stopped")


if __name__ == "__main__":
    sys.exit(0 if main() is None else 0)
