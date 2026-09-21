#!/usr/bin/env python3
"""Transparent bridge manager.

Creates a Linux bridge between the onboard ethernet (uplink to the
network) and a USB-ethernet adapter (downstream to the legitimate
device).  The bridge forwards all frames transparently so the switch
sees only the legitimate device's MAC.

The bridge name is auto-detected at runtime — if br0 is already
occupied by a system-managed bridge, LandNav tries br1, br2, etc.
until it finds an available name.

ebtables SNAT rewrites the Pi's outgoing MAC to match the legitimate
device, achieving full Layer-2 invisibility.

Port security bypass (v0.16.0):
  1. macvlan + DHCP — isolated L3 stack with DHCP snooping table entry
  2. macvlan + static — isolated L3 stack with find_unused_ip()
  3. IP piggyback — share the legitimate device's IP (ARP-silent)
  4. Legacy static — direct IP on br0 (last resort)
"""

import logging
import os
import re as _re
import shutil
import subprocess
import time
from pathlib import Path

from lib import netconfig

log = logging.getLogger("landnav.bridge")

BRIDGE_NAME = "br0"
MACVLAN_NAME = "macvlan0"
_DHCLIENT_CONF = Path("/tmp/landnav_dhclient.conf")

# ── Helpers ─────────────────────────────────────────────────────

def _run(cmd, check=True, timeout=15):
    log.debug("exec: %s", " ".join(cmd) if isinstance(cmd, list) else cmd)
    return subprocess.run(
        cmd, capture_output=True, text=True,
        check=check, timeout=timeout,
    )

def _has(binary):
    return shutil.which(binary) is not None

# Marker file — only bridges LandNav created carry this marker.
# destroy_bridge() refuses to touch a bridge without it.
_LANDNAV_BRIDGE_MARKER = Path("/var/run/landnav_bridge_managed")

# ── Bridge nf-call ──────────────────────────────────────────────

def _disable_bridge_nf_call():
    """Prevent iptables from filtering bridged L2 frames.

    Without this, Kali's default iptables FORWARD DROP policy silently
    drops frames traversing the bridge — the downstream device loses
    all network access.
    """
    _run(["modprobe", "br_netfilter"], check=False)
    for param in (
        "net.bridge.bridge-nf-call-iptables",
        "net.bridge.bridge-nf-call-ip6tables",
        "net.bridge.bridge-nf-call-arptables",
    ):
        _run(["sysctl", "-w", f"{param}=0"], check=False)

# ── Startup Cleanup ────────────────────────────────────────────

def cleanup_stale_bridges():
    """Remove non-system-managed bridges left by a prior LandNav run.

    Scans br1-br255 for bridges that are not system-managed, releases
    their member interfaces, and deletes them.  This frees interfaces
    like eth1 that would otherwise be invisible to detect_interfaces()
    because their brport/ sysfs entry still exists.

    Called once at startup before interface detection.
    """
    cleaned = 0
    for i in range(1, 256):
        name = f"br{i}"
        if not netconfig.interface_exists(name):
            continue
        if netconfig.is_system_managed_bridge(name):
            continue
        members = netconfig.get_bridge_ports(name)
        log.info("Cleaning stale bridge %s (members: %s)", name, members)
        try:
            for member in members:
                _run(["ip", "link", "set", member, "nomaster"], check=False)
            _run(["ip", "link", "set", name, "down"], check=False)
            _run(["ip", "link", "del", name], check=False)
            cleaned += 1
        except Exception as e:
            log.warning("Failed to clean bridge %s: %s", name, e)
    if cleaned:
        log.info("Cleaned %d stale bridge(s)", cleaned)
    _LANDNAV_BRIDGE_MARKER.unlink(missing_ok=True)

    # Clean stale macvlan from prior run
    destroy_macvlan()

# ── Pre-Bridge MAC Cloning (Port Security Bypass) ──────────────

def sniff_downstream_mac(downstream_iface, timeout=30):
    """Detect the legitimate device's MAC BEFORE bridge creation.

    Brings up only the downstream interface and sniffs for L2 frames.
    Also sends ARP probes to provoke an immediate response from the
    connected device.  Returns the MAC or None on timeout.

    This must run before any traffic is sent on the uplink interface,
    so the switch never sees the Pi's real MAC address.
    """
    log.info("Pre-bridge MAC detection on %s (timeout %ds)", downstream_iface, timeout)

    # Bring up downstream only — uplink stays down so nothing hits the switch
    try:
        _run(["ip", "link", "set", downstream_iface, "up"], check=False)
    except Exception:
        pass

    time.sleep(0.5)

    import re

    deadline = time.time() + timeout

    # Send broadcast ARP probes in background to provoke a response
    if _has("arping"):
        try:
            subprocess.Popen(
                ["arping", "-c", "10", "-w", str(min(timeout, 15)),
                 "-I", downstream_iface, "-D", "0.0.0.0"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    # Sniff with tcpdump for any inbound unicast frame
    if _has("tcpdump"):
        while time.time() < deadline:
            remaining = int(deadline - time.time())
            if remaining <= 0:
                break
            try:
                r = _run(
                    ["timeout", str(min(remaining, 10)),
                     "tcpdump", "-c", "1", "-e", "-l",
                     "-i", downstream_iface, "-Q", "in",
                     "not", "ether", "broadcast",
                     "and", "not", "ether", "multicast"],
                    check=False, timeout=min(remaining, 12),
                )
                output = (r.stdout or "") + (r.stderr or "")
                m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", output, re.I)
                if m:
                    mac = m.group(1).lower()
                    if not mac.startswith("ff:ff:") and not mac.startswith("33:33:"):
                        log.info("Downstream device MAC detected: %s", mac)
                        return mac
            except Exception as e:
                log.debug("tcpdump attempt: %s", e)
            time.sleep(1)

    # Fallback: read neighbor table
    try:
        r = _run(["ip", "neigh", "show", "dev", downstream_iface], check=False)
        if r.returncode == 0:
            m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", r.stdout, re.I)
            if m:
                mac = m.group(1).lower()
                log.info("Downstream device MAC (neighbor table): %s", mac)
                return mac
    except Exception:
        pass

    log.warning("Could not detect downstream device MAC within %ds", timeout)
    return None


def clone_mac(iface, mac):
    """Set an interface's hardware MAC address.

    The interface is brought down, MAC changed, then brought back up.
    This must be done BEFORE the interface joins a bridge or sends any
    frames, so the switch only ever sees the cloned MAC.
    """
    log.info("Cloning MAC %s onto %s", mac, iface)
    try:
        _run(["ip", "link", "set", iface, "down"])
        _run(["ip", "link", "set", iface, "address", mac])
        _run(["ip", "link", "set", iface, "up"])
        log.info("MAC clone successful: %s is now %s", iface, mac)
        return True
    except subprocess.CalledProcessError as e:
        log.error("MAC clone failed on %s: %s", iface, e.stderr)
        return False


# ── Bridge Lifecycle ────────────────────────────────────────────

def _existing_bridge_usable(uplink, downstream):
    """Check if BRIDGE_NAME already exists with the ports we need.

    Returns:
        "usable"     — bridge exists, has IP, has our ports — use as-is
        "compatible" — bridge exists and has our uplink — we can add downstream
        "foreign"    — bridge exists but is system-managed — must not touch
        None         — no bridge exists
    """
    if not netconfig.interface_exists(BRIDGE_NAME):
        return None

    # NEVER touch a system-managed bridge
    if netconfig.is_system_managed_bridge(BRIDGE_NAME):
        members = netconfig.get_bridge_ports(BRIDGE_NAME)
        info = netconfig.get_interface_info(BRIDGE_NAME)
        log.info("Existing system-managed bridge %s detected: members=%s ip=%s",
                 BRIDGE_NAME, members, info["ip"])
        return "foreign"

    members = set(netconfig.get_bridge_ports(BRIDGE_NAME))
    info = netconfig.get_interface_info(BRIDGE_NAME)

    if uplink in members and downstream in members:
        if info["ip"] and info["state"] == "UP":
            return "usable"

    if uplink in members:
        return "compatible"

    return "foreign"


def create_bridge(uplink, downstream, stp=False):
    """Create a bridge between uplink (wall port) and downstream (legit device).

    Auto-detects an available bridge name — if br0 is occupied by a
    system-managed bridge, tries br1, br2, etc. up to br255.

    After creation, disables bridge-nf-call-iptables so the kernel's
    iptables FORWARD chain does not drop bridged L2 frames.

    Args:
        uplink:     Interface name connected to the wall (e.g. eth0)
        downstream: Interface name connected to legit device (e.g. eth1)
        stp:        Enable spanning tree (default False — avoids topology alerts)

    Returns:
        True on success, False on failure.
    """
    global BRIDGE_NAME

    # ── Auto-detect available bridge name ─────────────────────
    for i in range(256):
        candidate = f"br{i}"
        if not netconfig.interface_exists(candidate):
            BRIDGE_NAME = candidate
            break
        if not netconfig.is_system_managed_bridge(candidate):
            BRIDGE_NAME = candidate
            break
        log.info("br%d is system-managed — skipping", i)
    else:
        log.error("No available bridge name (br0-br255 all system-managed)")
        return False

    log.info("Creating bridge %s: %s (uplink) + %s (downstream)",
             BRIDGE_NAME, uplink, downstream)

    # ── Check for existing bridge with this name ──────────────
    status = _existing_bridge_usable(uplink, downstream)

    if status == "foreign":
        log.warning("Bridge %s exists but is unmanaged with wrong ports — "
                    "enabling promiscuous mode as fallback", BRIDGE_NAME)
        try:
            netconfig.set_interface_promisc(BRIDGE_NAME, True)
        except Exception:
            pass
        return True

    if status == "usable":
        log.info("Existing bridge %s already has correct ports and IP — reusing",
                 BRIDGE_NAME)
        try:
            netconfig.set_interface_promisc(BRIDGE_NAME, True)
        except Exception:
            pass
        _LANDNAV_BRIDGE_MARKER.write_text(str(os.getpid()))
        _disable_bridge_nf_call()
        return True

    if status == "compatible":
        log.info("Existing bridge %s has uplink — adding downstream %s",
                 BRIDGE_NAME, downstream)
        try:
            _run(["ip", "link", "set", downstream, "master", BRIDGE_NAME])
            netconfig.set_interface_up(downstream)
            netconfig.set_interface_promisc(BRIDGE_NAME, True)
            _LANDNAV_BRIDGE_MARKER.write_text(str(os.getpid()))
            _disable_bridge_nf_call()
            log.info("Downstream %s added to existing bridge", downstream)
            return True
        except subprocess.CalledProcessError as e:
            log.error("Failed to add %s to bridge: %s", downstream, e.stderr)
            return False

    # ── No usable bridge — create from scratch ─────────────────
    try:
        # Only destroy a previous LandNav-created bridge (marker file check)
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

        # Disable iptables on bridged frames
        _disable_bridge_nf_call()

        # Mark this bridge as LandNav-managed
        _LANDNAV_BRIDGE_MARKER.write_text(str(os.getpid()))

        log.info("Bridge %s created successfully", BRIDGE_NAME)
        return True

    except subprocess.CalledProcessError as e:
        log.error("Bridge creation failed: %s — stderr: %s", e, e.stderr)
        return False
    except Exception as e:
        log.error("Bridge creation failed: %s", e)
        return False


def destroy_bridge():
    """Tear down the LandNav bridge and release member interfaces.

    SAFETY: Refuses to destroy a system-managed bridge (defined in
    /etc/network/interfaces, NetworkManager, or netplan).  Only destroys
    bridges that LandNav created (indicated by the marker file).
    """
    # Clean up macvlan first
    destroy_macvlan()

    if not netconfig.interface_exists(BRIDGE_NAME):
        _LANDNAV_BRIDGE_MARKER.unlink(missing_ok=True)
        return

    # NEVER destroy a system-managed bridge
    if netconfig.is_system_managed_bridge(BRIDGE_NAME):
        log.info("Bridge %s is system-managed — leaving it intact", BRIDGE_NAME)
        _LANDNAV_BRIDGE_MARKER.unlink(missing_ok=True)
        return

    # Only destroy if LandNav created it
    if not _LANDNAV_BRIDGE_MARKER.exists():
        log.info("Bridge %s exists but was not created by LandNav — leaving it intact",
                 BRIDGE_NAME)
        return

    log.info("Destroying LandNav-managed bridge %s", BRIDGE_NAME)

    try:
        # Remove ebtables rules
        clear_mac_transparency()

        netconfig.set_interface_down(BRIDGE_NAME)
        _run(["ip", "link", "del", BRIDGE_NAME], check=False)
    except Exception as e:
        log.warning("Bridge teardown: %s", e)
    finally:
        _LANDNAV_BRIDGE_MARKER.unlink(missing_ok=True)


def bridge_is_up():
    """Check if the LandNav bridge exists and is UP."""
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

def add_port(iface):
    """Add an interface as a new port on the current bridge.

    Used when a system-managed bridge already has the uplink and
    connectivity — the downstream (USB-ethernet) is added to it
    so the connected device gets transparent L2 access.
    """
    log.info("Adding %s to bridge %s", iface, BRIDGE_NAME)
    try:
        _run(["ip", "link", "set", iface, "master", BRIDGE_NAME])
        netconfig.set_interface_up(iface)
        netconfig.set_interface_promisc(BRIDGE_NAME, True)
        _disable_bridge_nf_call()
        log.info("Port %s added to bridge %s", iface, BRIDGE_NAME)
        return True
    except subprocess.CalledProcessError as e:
        log.error("Failed to add %s to bridge %s: %s", iface, BRIDGE_NAME, e.stderr)
        return False


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

# ── macvlan for Pi's Network Stack (Port Security Bypass) ──────

def create_macvlan(parent_iface, legit_mac):
    """Create a macvlan on the uplink for the Pi's isolated L3 stack.

    The macvlan uses the legitimate device's MAC natively so port
    security sees a single MAC on the wire.  Created on the physical
    uplink BEFORE bridge creation — the macvlan persists independently
    of the bridge's forwarding path.

    Return traffic reaches the Pi via macvlan MAC match; bridge-
    forwarded traffic reaches the legitimate device via FDB lookup.
    """
    log.info("Creating macvlan %s on %s (MAC %s)", MACVLAN_NAME, parent_iface, legit_mac)
    try:
        _run(["ip", "link", "del", MACVLAN_NAME], check=False)

        _run(["ip", "link", "add", MACVLAN_NAME, "link", parent_iface,
              "type", "macvlan", "mode", "bridge"])
        _run(["ip", "link", "set", MACVLAN_NAME, "address", legit_mac])
        suppress_ipv6(MACVLAN_NAME)
        _run(["ip", "link", "set", MACVLAN_NAME, "up"])

        log.info("macvlan %s created on %s", MACVLAN_NAME, parent_iface)
        return True
    except subprocess.CalledProcessError as e:
        log.error("macvlan creation failed: %s", e.stderr)
        return False


def dhcp_macvlan(iface=None, timeout=30):
    """Obtain a DHCP lease on the macvlan with a unique client-id.

    A distinct client-id makes the DHCP server treat the Pi as a
    separate client from the legitimate device, assigning a different
    IP.  That new IP enters the DHCP snooping table so Dynamic ARP
    Inspection validates the Pi's ARP requests.

    Returns dict with ip/cidr on success, None on failure.
    """
    iface = iface or MACVLAN_NAME

    import random
    import string
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    client_id = f"DESKTOP-{suffix}"

    conf = (
        f'interface "{iface}" {{\n'
        f'    send dhcp-client-identifier "{client_id}";\n'
        f'    send host-name "{client_id}";\n'
        f'}}\n'
    )
    _DHCLIENT_CONF.write_text(conf)

    log.info("DHCP on %s (client-id: %s, timeout %ds)", iface, client_id, timeout)
    _run(["dhclient", "-r", iface], check=False, timeout=10)

    try:
        _run(["dhclient", "-1", "-v", "-cf", str(_DHCLIENT_CONF), iface],
             check=False, timeout=timeout)
        info = netconfig.get_interface_info(iface)
        if info["ip"]:
            log.info("DHCP on %s: IP=%s/%s", iface, info["ip"], info["cidr"])
            return info
        log.warning("dhclient exited without IP on %s", iface)
        return None
    except subprocess.TimeoutExpired:
        log.warning("dhclient timed out on %s", iface)
        _run(["dhclient", "-r", iface], check=False, timeout=5)
        return None
    finally:
        _DHCLIENT_CONF.unlink(missing_ok=True)


def configure_macvlan_ip(ip, cidr, gateway, dns_servers=None, domain=None):
    """Assign a static IP to the macvlan for Pi's connectivity."""
    log.info("Static IP on %s: %s/%d gw %s", MACVLAN_NAME, ip, cidr, gateway)
    netconfig.set_ip(MACVLAN_NAME, ip, cidr)
    netconfig.set_default_route(gateway, MACVLAN_NAME)
    if dns_servers:
        netconfig.set_dns(dns_servers, domain)


def setup_ip_piggyback(legit_ip, gateway, dns_servers=None, domain=None):
    """Share the legitimate device's IP on the bridge (fallback).

    Assigns the legitimate device's IP to br0 with ARP suppression
    so the Pi never broadcasts conflicting ARP announcements.  A
    static ARP entry for the gateway lets the Pi reach the network
    without issuing its own ARP requests.

    All outbound frames already carry the legitimate device's MAC
    (via ebtables SNAT), so port security + DHCP snooping + DAI
    see one consistent identity on the wire.
    """
    log.info("IP piggyback: using legit IP %s on %s", legit_ip, BRIDGE_NAME)

    suppress_ipv6(BRIDGE_NAME)

    # Suppress ARP announcements — the legitimate device handles ARP
    _run(["sysctl", "-w", f"net.ipv4.conf.{BRIDGE_NAME}.arp_announce=2"], check=False)
    _run(["sysctl", "-w", f"net.ipv4.conf.{BRIDGE_NAME}.arp_notify=0"], check=False)
    _run(["sysctl", "-w", f"net.ipv4.conf.{BRIDGE_NAME}.arp_ignore=8"], check=False)

    # Learn gateway's MAC from neighbor table (populated by bridge sniffing)
    gw_mac = None
    try:
        r = _run(["ip", "neigh", "show", gateway], check=False)
        m = _re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", r.stdout, _re.I)
        if m:
            gw_mac = m.group(1)
    except Exception:
        pass

    netconfig.flush_interface(BRIDGE_NAME)
    _run(["ip", "addr", "add", f"{legit_ip}/32", "dev", BRIDGE_NAME,
          "noprefixroute"], check=False)

    if gw_mac:
        _run(["ip", "neigh", "replace", gateway, "lladdr", gw_mac,
              "nud", "permanent", "dev", BRIDGE_NAME], check=False)
        log.info("Static ARP: %s -> %s", gateway, gw_mac)

    _run(["ip", "route", "add", f"{gateway}/32", "dev", BRIDGE_NAME], check=False)
    netconfig.set_default_route(gateway, BRIDGE_NAME)

    if dns_servers:
        netconfig.set_dns(dns_servers, domain)

    log.info("IP piggyback active: %s on %s", legit_ip, BRIDGE_NAME)
    return True


def destroy_macvlan():
    """Remove macvlan interface and release any DHCP lease."""
    if not netconfig.interface_exists(MACVLAN_NAME):
        return
    try:
        _run(["dhclient", "-r", MACVLAN_NAME], check=False, timeout=5)
    except Exception:
        pass
    _run(["ip", "link", "del", MACVLAN_NAME], check=False)
    _DHCLIENT_CONF.unlink(missing_ok=True)
    log.info("macvlan %s destroyed", MACVLAN_NAME)


def suppress_ipv6(iface):
    """Disable IPv6 to prevent NDP leaking the Pi's real MAC via EUI-64."""
    _run(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"], check=False)
