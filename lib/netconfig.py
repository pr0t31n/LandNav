#!/usr/bin/env python3
"""Network configuration abstraction.

Uses `ip` commands for all runtime configuration — no dependency on
/etc/network/interfaces or netplan.  Those backends are only relevant
for the installer (boot-time service ordering).

All functions are idempotent and safe to re-call.
"""

import ipaddress
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("landnav.netconfig")

# ── Helpers ─────────────────────────────────────────────────────

def _run(cmd, check=True, timeout=30):
    """Run a command, return CompletedProcess."""
    log.debug("exec: %s", " ".join(cmd) if isinstance(cmd, list) else cmd)
    return subprocess.run(
        cmd, capture_output=True, text=True,
        check=check, timeout=timeout,
    )

def _has(binary):
    return shutil.which(binary) is not None

# ── Interface Detection ─────────────────────────────────────────

def detect_interfaces():
    """Detect available ethernet interfaces.

    Returns:
        dict with keys:
            onboard: str or None — onboard ethernet (eth0, end0, etc.)
            usb_eth: str or None — USB ethernet adapter (eth1, enx*, usb0, etc.)
            all_eth: list[str] — all detected ethernet interfaces
    """
    result = {"onboard": None, "usb_eth": None, "all_eth": []}
    sys_net = Path("/sys/class/net")

    for iface in sorted(sys_net.iterdir()):
        name = iface.name
        if name == "lo" or name.startswith("br") or name.startswith("dns"):
            continue

        itype = (iface / "type").read_text().strip() if (iface / "type").exists() else ""
        if itype != "1":  # 1 = ARPHRD_ETHER
            continue

        # Skip wireless
        if (iface / "wireless").exists() or (iface / "phy80211").exists():
            continue

        device_path = (iface / "device").resolve() if (iface / "device").is_symlink() else None
        is_usb = device_path and "usb" in str(device_path).lower() if device_path else False

        # Also detect by name pattern
        if not is_usb and (name.startswith("enx") or name.startswith("usb")):
            is_usb = True

        result["all_eth"].append(name)

        if is_usb and result["usb_eth"] is None:
            result["usb_eth"] = name
        elif not is_usb and result["onboard"] is None:
            result["onboard"] = name

    # If we found two+ ethernets but couldn't classify, assume first=onboard second=USB
    if result["onboard"] is None and len(result["all_eth"]) >= 1:
        result["onboard"] = result["all_eth"][0]
    if result["usb_eth"] is None and len(result["all_eth"]) >= 2:
        result["usb_eth"] = result["all_eth"][1]

    return result


def get_interface_info(iface):
    """Get MAC, IP, state for an interface.

    Returns:
        dict: mac, ip, netmask, cidr, state (UP/DOWN/UNKNOWN)
    """
    info = {"mac": None, "ip": None, "netmask": None, "cidr": None, "state": "UNKNOWN"}

    try:
        mac_path = Path(f"/sys/class/net/{iface}/address")
        if mac_path.exists():
            info["mac"] = mac_path.read_text().strip()

        operstate = Path(f"/sys/class/net/{iface}/operstate")
        if operstate.exists():
            info["state"] = operstate.read_text().strip().upper()

        r = _run(["ip", "-4", "addr", "show", iface], check=False)
        if r.returncode == 0:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", r.stdout)
            if m:
                info["ip"] = m.group(1)
                info["cidr"] = int(m.group(2))
                net = ipaddress.IPv4Network(f"{m.group(1)}/{m.group(2)}", strict=False)
                info["netmask"] = str(net.netmask)
    except Exception as e:
        log.warning("get_interface_info(%s): %s", iface, e)

    return info


def interface_exists(iface):
    return Path(f"/sys/class/net/{iface}").exists()


def interface_has_carrier(iface):
    """Check if a physical link is present (cable plugged in)."""
    try:
        return Path(f"/sys/class/net/{iface}/carrier").read_text().strip() == "1"
    except (OSError, ValueError):
        return False

# ── Interface Configuration ─────────────────────────────────────

def set_interface_up(iface):
    log.info("Bringing up %s", iface)
    _run(["ip", "link", "set", iface, "up"])


def set_interface_down(iface):
    log.info("Bringing down %s", iface)
    _run(["ip", "link", "set", iface, "down"], check=False)


def set_interface_mac(iface, mac):
    """Set MAC address. Interface must be down."""
    log.info("Setting %s MAC to %s", iface, mac)
    _run(["ip", "link", "set", iface, "address", mac])


def set_interface_promisc(iface, on=True):
    mode = "on" if on else "off"
    _run(["ip", "link", "set", iface, "promisc", mode])


def flush_interface(iface):
    """Remove all addresses and routes from interface."""
    _run(["ip", "addr", "flush", "dev", iface], check=False)
    _run(["ip", "route", "flush", "dev", iface], check=False)

# ── IP Configuration ────────────────────────────────────────────

def set_ip(iface, ip, cidr=24):
    """Assign an IP address to an interface."""
    log.info("Assigning %s/%d to %s", ip, cidr, iface)
    flush_interface(iface)
    _run(["ip", "addr", "add", f"{ip}/{cidr}", "dev", iface])


def set_default_route(gateway, iface=None):
    """Set the default gateway."""
    log.info("Setting default route via %s", gateway)
    _run(["ip", "route", "del", "default"], check=False)
    cmd = ["ip", "route", "add", "default", "via", gateway]
    if iface:
        cmd += ["dev", iface]
    _run(cmd)


def set_dns(servers, domain=None):
    """Write /etc/resolv.conf with the given DNS servers."""
    lines = []
    if domain:
        lines.append(f"search {domain}")
    for s in servers:
        lines.append(f"nameserver {s}")

    content = "\n".join(lines) + "\n"
    log.info("Setting DNS: %s", ", ".join(servers))
    Path("/etc/resolv.conf").write_text(content)

# ── DHCP Client ─────────────────────────────────────────────────

def run_dhclient(iface, timeout=30):
    """Run dhclient to obtain a DHCP lease. Returns True on success."""
    log.info("Running dhclient on %s (timeout %ds)", iface, timeout)
    # Kill any existing dhclient for this interface
    _run(["dhclient", "-r", iface], check=False, timeout=10)

    try:
        r = _run(["dhclient", "-1", "-v", iface], check=False, timeout=timeout)
        info = get_interface_info(iface)
        if info["ip"]:
            log.info("DHCP acquired: %s on %s", info["ip"], iface)
            return True
        log.warning("dhclient exited but no IP assigned on %s", iface)
        return False
    except subprocess.TimeoutExpired:
        log.warning("dhclient timed out on %s", iface)
        _run(["dhclient", "-r", iface], check=False, timeout=5)
        return False


def release_dhcp(iface):
    _run(["dhclient", "-r", iface], check=False, timeout=10)

# ── Connectivity Tests ──────────────────────────────────────────

def can_reach_gateway(gateway, timeout=3):
    """ARP-level reachability check (Layer 2)."""
    if not _has("arping"):
        return ping(gateway, timeout=timeout)
    r = _run(
        ["arping", "-c", "1", "-w", str(timeout), gateway],
        check=False, timeout=timeout + 2,
    )
    return r.returncode == 0


def ping(host, count=1, timeout=3):
    """ICMP ping. Returns True if host responds."""
    r = _run(
        ["ping", "-c", str(count), "-W", str(timeout), host],
        check=False, timeout=timeout + 5,
    )
    return r.returncode == 0


def dns_resolves(hostname="example.com", server=None, timeout=5):
    """Test DNS resolution. Returns resolved IP or None."""
    cmd = ["nslookup", hostname]
    if server:
        cmd.append(server)
    try:
        r = _run(cmd, check=False, timeout=timeout)
        if r.returncode == 0 and "Address" in r.stdout:
            # Parse the answer (skip the server line)
            for line in r.stdout.splitlines():
                if line.startswith("Address") and "#" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[-1]
        return None
    except subprocess.TimeoutExpired:
        return None


def internet_reachable(timeout=5):
    """Check if we can reach the internet (DNS + HTTP)."""
    # Try DNS first
    resolved = dns_resolves("example.com", timeout=timeout)
    if not resolved:
        return False
    # Try TCP connect to port 80
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((resolved, 80))
        s.close()
        return True
    except (socket.error, OSError):
        return False

# ── Networking Backend Detection (for installer) ───────────────

def detect_networking_backend():
    """Detect which networking backend the system uses.

    Returns: 'networkmanager', 'netplan', 'interfaces', or 'unknown'
    """
    # Check NetworkManager
    if _has("nmcli"):
        r = _run(["nmcli", "-t", "-f", "RUNNING", "general"], check=False, timeout=5)
        if r.returncode == 0 and "running" in r.stdout.lower():
            return "networkmanager"

    # Check netplan
    if _has("netplan") and any(Path("/etc/netplan").glob("*.yaml")):
        return "netplan"

    # Check /etc/network/interfaces
    if Path("/etc/network/interfaces").exists():
        return "interfaces"

    return "unknown"
