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
Verification is pod-readiness based: after writing the peer secret and
restarting the scanner, we wait for the netscan pod to become Ready. Ready =
gluetun's tunnel is up. Not ready in time = handshake failed = reprovision.
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


def kubectl(args, stdin=None, check=True):
    p = subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


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
wg-quick up wg0
"""


def apply(manifest):
    kubectl(["apply", "-f", "-"], stdin=json.dumps(manifest))


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


def scanner_ready(timeout=100):
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = kubectl(["rollout", "status", f"deploy/{DEPLOY}", "-n", NS,
                       "--timeout=10s"], check=False)
        if "successfully rolled out" in out:
            return True
        time.sleep(5)
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
        if scanner_ready():
            log(f"tunnel UP — scans now exit {ip} ({region}). Holding box up.")
            return True
        log("scanner did not become ready (handshake failed) — reprovisioning")
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
