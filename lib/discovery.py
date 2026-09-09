#!/usr/bin/env python3
"""Network discovery module.

Passively and actively discovers network configuration:
  - DHCP sniffing (from legitimate device traffic through the bridge)
  - ARP observation (gateway, active hosts, subnet)
  - LLDP/CDP parsing (switch info, VLAN, management IP)
  - Smart subnet probing (ARP-based, not brute-force-first)
  - Proxy detection (WPAD, common ports)
  - DNS server discovery
"""

import ipaddress
import logging
import re
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

log = logging.getLogger("landnav.discovery")

# ── Common Gateways ────────────────────────────────────────────

COMMON_GATEWAY_OCTETS = [1, 254, 2, 100, 10, 50, 129]

# RFC 1918 probe order — most common ranges first
PROBE_SUBNETS = [
    "192.168.1", "192.168.0", "10.0.0", "10.0.1",
    "172.16.0", "172.16.1", "192.168.10", "192.168.100",
    "10.1.0", "10.1.1", "10.10.0", "10.10.10",
    "192.168.2", "192.168.5", "192.168.50", "192.168.254",
    "172.16.10", "172.17.0", "172.20.0", "172.31.0",
    "10.100.0", "10.200.0", "10.255.0",
]

COMMON_PROXY_PORTS = [8080, 3128, 8888, 8443, 9090, 80]


class NetworkConfig:
    """Discovered network configuration."""

    def __init__(self):
        self.ip = None
        self.netmask = None
        self.cidr = None
        self.gateway = None
        self.dns_servers = []
        self.domain = None
        self.client_mac = None
        self.client_ip = None
        self.vlan = None
        self.hosts = {}           # ip -> mac
        self.lease_time = None
        self.proxy_host = None
        self.proxy_port = None
        self.discovery_method = None

    def is_complete(self):
        return all([self.gateway, self.cidr])

    def __repr__(self):
        return (f"NetworkConfig(gw={self.gateway}, cidr={self.cidr}, "
                f"dns={self.dns_servers}, method={self.discovery_method})")

# ── DHCP Sniffing ───────────────────────────────────────────────

def sniff_dhcp(iface, timeout=60):
    """Sniff DHCP traffic to learn network configuration.

    Uses scapy for structured packet parsing. Falls back to
    tcpdump if scapy is unavailable.

    Returns: NetworkConfig (may be partial)
    """
    config = NetworkConfig()
    config.discovery_method = "dhcp_sniff"

    try:
        from scapy.all import sniff as scapy_sniff, DHCP, BOOTP, Ether, conf
        conf.verb = 0  # suppress scapy output

        log.info("Sniffing DHCP on %s for %ds (scapy)", iface, timeout)

        packets = scapy_sniff(
            iface=iface,
            filter="udp and (port 67 or port 68)",
            timeout=timeout,
            store=True,
        )

        for pkt in packets:
            if DHCP not in pkt:
                continue

            opts = {}
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opts[opt[0]] = opt[1]

            msg_type = opts.get("message-type", 0)

            # Discover/Request — learn client MAC and requested IP
            if msg_type in (1, 3):
                if Ether in pkt:
                    config.client_mac = pkt[Ether].src
                if BOOTP in pkt and pkt[BOOTP].ciaddr != "0.0.0.0":
                    config.client_ip = pkt[BOOTP].ciaddr
                req_ip = opts.get("requested_addr")
                if req_ip:
                    config.client_ip = req_ip

            # Offer/ACK — full network config
            if msg_type in (2, 5):
                if BOOTP in pkt:
                    offered = pkt[BOOTP].yiaddr
                    if offered and offered != "0.0.0.0":
                        config.client_ip = offered

                if Ether in pkt and not config.client_mac:
                    config.client_mac = pkt[Ether].dst

                router = opts.get("router")
                if router:
                    config.gateway = router if isinstance(router, str) else router[0]

                mask = opts.get("subnet_mask")
                if mask:
                    config.netmask = mask
                    config.cidr = _mask_to_cidr(mask)

                dns = opts.get("name_server")
                if dns:
                    if isinstance(dns, (list, tuple)):
                        config.dns_servers = list(dns)
                    elif isinstance(dns, str):
                        config.dns_servers = [dns]

                domain = opts.get("domain")
                if domain:
                    config.domain = domain if isinstance(domain, str) else domain.decode()

                lease = opts.get("lease_time")
                if lease:
                    config.lease_time = lease

        if config.gateway:
            log.info("DHCP sniff successful: gw=%s mask=%s dns=%s client=%s",
                     config.gateway, config.netmask, config.dns_servers,
                     config.client_ip)
        else:
            log.info("DHCP sniff: no Offer/ACK captured in %ds", timeout)

    except ImportError:
        log.warning("scapy not available — falling back to tcpdump DHCP sniff")
        config = _sniff_dhcp_tcpdump(iface, timeout)

    return config


def _sniff_dhcp_tcpdump(iface, timeout):
    """Fallback DHCP sniffer using tcpdump + manual parsing."""
    config = NetworkConfig()
    config.discovery_method = "dhcp_tcpdump"

    try:
        r = subprocess.run(
            ["timeout", str(timeout), "tcpdump", "-vvv", "-n", "-i", iface,
             "-c", "20", "port", "67", "or", "port", "68"],
            capture_output=True, text=True, check=False, timeout=timeout + 5,
        )
        output = r.stdout + r.stderr

        # Parse gateway from "Router" option
        m = re.search(r"Router\s+(?:Option\s+\d+,\s+length\s+\d+:\s+)?(\d+\.\d+\.\d+\.\d+)", output)
        if m:
            config.gateway = m.group(1)

        # Parse subnet mask
        m = re.search(r"Subnet-Mask\s+(?:Option\s+\d+,\s+length\s+\d+:\s+)?(\d+\.\d+\.\d+\.\d+)", output)
        if m:
            config.netmask = m.group(1)
            config.cidr = _mask_to_cidr(m.group(1))

        # Parse DNS
        m = re.search(r"Domain-Name-Server\s+(?:Option\s+\d+,\s+length\s+\d+:\s+)?([\d.,\s]+)", output)
        if m:
            config.dns_servers = [ip.strip() for ip in m.group(1).split(",")
                                  if re.match(r"\d+\.\d+\.\d+\.\d+", ip.strip())]

        # Parse offered IP
        m = re.search(r"Your-IP\s+(\d+\.\d+\.\d+\.\d+)", output)
        if m:
            config.client_ip = m.group(1)

    except Exception as e:
        log.warning("tcpdump DHCP fallback failed: %s", e)

    return config

# ── ARP Sniffing ────────────────────────────────────────────────

def sniff_arp(iface, timeout=60):
    """Passive ARP observation to learn hosts and gateway candidates.

    Returns: NetworkConfig (partial — typically gateway + hosts)
    """
    config = NetworkConfig()
    config.discovery_method = "arp_sniff"

    try:
        from scapy.all import sniff as scapy_sniff, ARP, conf
        conf.verb = 0

        log.info("Sniffing ARP on %s for %ds", iface, timeout)

        packets = scapy_sniff(
            iface=iface, filter="arp", timeout=timeout, store=True,
        )

        gateway_scores = {}  # ip -> score (higher = more likely gateway)

        for pkt in packets:
            if ARP not in pkt:
                continue

            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

            if src_ip == "0.0.0.0":
                continue

            config.hosts[src_ip] = src_mac

            # Score gateway candidates
            last_octet = int(src_ip.split(".")[-1])
            if last_octet in (1, 254, 2, 100):
                gateway_scores[src_ip] = gateway_scores.get(src_ip, 0) + 5
            if pkt[ARP].op == 2:  # is-at reply (active responder)
                gateway_scores[src_ip] = gateway_scores.get(src_ip, 0) + 2

        # Highest-scoring candidate is likely the gateway
        if gateway_scores:
            config.gateway = max(gateway_scores, key=gateway_scores.get)
            log.info("ARP sniff: likely gateway %s (score %d), %d hosts seen",
                     config.gateway, gateway_scores[config.gateway], len(config.hosts))

            # Derive subnet from observed IPs
            config.cidr = _infer_cidr(list(config.hosts.keys()))
        else:
            log.info("ARP sniff: no traffic observed in %ds", timeout)

    except ImportError:
        log.warning("scapy not available — using tcpdump ARP fallback")
        config = _sniff_arp_tcpdump(iface, timeout)

    return config


def _sniff_arp_tcpdump(iface, timeout):
    """Fallback ARP sniffer using tcpdump."""
    config = NetworkConfig()
    config.discovery_method = "arp_tcpdump"

    try:
        r = subprocess.run(
            ["timeout", str(timeout), "tcpdump", "-l", "-n", "-e",
             "-i", iface, "arp"],
            capture_output=True, text=True, check=False, timeout=timeout + 5,
        )

        ips = set()
        for line in r.stdout.splitlines():
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", line):
                ip = m.group(1)
                if ip != "0.0.0.0":
                    ips.add(ip)

        for ip in ips:
            config.hosts[ip] = None
            last = int(ip.split(".")[-1])
            if last in COMMON_GATEWAY_OCTETS and not config.gateway:
                config.gateway = ip

        if config.hosts:
            config.cidr = _infer_cidr(list(config.hosts.keys()))

    except Exception as e:
        log.warning("tcpdump ARP fallback failed: %s", e)

    return config

# ── LLDP / CDP Sniffing ────────────────────────────────────────

def sniff_lldp_cdp(iface, timeout=65):
    """Listen for LLDP and CDP frames from the switch.

    LLDP is sent every 30s, CDP every 60s.  A 65s timeout
    should catch at least one of each if enabled.

    Returns: dict with discovered switch info
    """
    info = {"switch_name": None, "port_desc": None, "vlan": None,
            "mgmt_ip": None, "platform": None}

    if not shutil.which("tcpdump"):
        return info

    log.info("Listening for LLDP/CDP on %s (%ds)", iface, timeout)

    try:
        r = subprocess.run(
            ["timeout", str(timeout), "tcpdump", "-vvv", "-n", "-c", "5",
             "-i", iface,
             "ether", "proto", "0x88cc", "or",
             "ether", "dst", "01:00:0c:cc:cc:cc"],
            capture_output=True, text=True, check=False, timeout=timeout + 5,
        )
        output = r.stdout + r.stderr

        # LLDP parsing
        m = re.search(r"System Name TLV.*?:\s*(.+)", output)
        if m:
            info["switch_name"] = m.group(1).strip()

        m = re.search(r"Port Description TLV.*?:\s*(.+)", output)
        if m:
            info["port_desc"] = m.group(1).strip()

        m = re.search(r"Management Address.*?(\d+\.\d+\.\d+\.\d+)", output)
        if m:
            info["mgmt_ip"] = m.group(1)

        # CDP parsing
        m = re.search(r"Device-ID.*?'([^']+)'", output)
        if m and not info["switch_name"]:
            info["switch_name"] = m.group(1)

        m = re.search(r"Native VLAN.*?(\d+)", output)
        if m:
            info["vlan"] = int(m.group(1))

        m = re.search(r"Platform.*?'([^']+)'", output)
        if m:
            info["platform"] = m.group(1)

        if any(v for v in info.values()):
            log.info("LLDP/CDP: %s", {k: v for k, v in info.items() if v})
        else:
            log.info("No LLDP/CDP frames received in %ds", timeout)

    except Exception as e:
        log.warning("LLDP/CDP sniff failed: %s", e)

    return info

# ── Active Subnet Probing ──────────────────────────────────────

def probe_for_gateway(iface, timeout_per_probe=2):
    """ARP-probe common gateways on common subnets.

    Much faster than brute-forcing IPs — sends targeted ARP who-has
    requests for likely gateway addresses and waits for replies.

    Returns: NetworkConfig or None
    """
    log.info("Probing common subnets for gateway (ARP)")

    if not shutil.which("arping"):
        log.warning("arping not found — cannot probe")
        return None

    for subnet in PROBE_SUBNETS:
        for octet in COMMON_GATEWAY_OCTETS:
            target = f"{subnet}.{octet}"
            try:
                r = subprocess.run(
                    ["arping", "-c", "1", "-w", str(timeout_per_probe),
                     "-I", iface, target],
                    capture_output=True, text=True,
                    check=False, timeout=timeout_per_probe + 3,
                )
                if r.returncode == 0 and "bytes from" in r.stdout.lower():
                    log.info("Gateway found via ARP probe: %s", target)
                    config = NetworkConfig()
                    config.discovery_method = "arp_probe"
                    config.gateway = target
                    config.cidr = 24  # Assume /24; will verify
                    # Extract MAC from arping output
                    m = re.search(r"\[([0-9a-fA-F:]{17})\]", r.stdout)
                    if m:
                        config.hosts[target] = m.group(1)
                    return config
            except (subprocess.TimeoutExpired, Exception):
                continue

    log.info("ARP probing did not find a gateway")
    return None


def find_unused_ip(gateway, cidr=24, preferred_octets=None, iface=None):
    """Find an unused IP address in the same subnet as the gateway.

    Args:
        gateway:          Gateway IP
        cidr:             Subnet CIDR
        preferred_octets: List of last-octet values to try first
        iface:            Interface for arping (optional)

    Returns: str IP address, or None
    """
    if preferred_octets is None:
        preferred_octets = [236, 237, 238, 235, 234, 233, 240, 241]

    network = ipaddress.IPv4Network(f"{gateway}/{cidr}", strict=False)
    base = str(network.network_address).rsplit(".", 1)[0]

    # Try preferred octets first
    for octet in preferred_octets:
        candidate = f"{base}.{octet}"
        if candidate == gateway:
            continue
        try:
            addr = ipaddress.IPv4Address(candidate)
            if addr not in network:
                continue
        except ValueError:
            continue

        if not _ip_in_use(candidate, iface):
            log.info("Found unused IP: %s", candidate)
            return candidate

    # Fallback: scan from .250 downward (avoid low DHCP range)
    for octet in range(250, 1, -1):
        candidate = f"{base}.{octet}"
        if candidate == gateway:
            continue
        if not _ip_in_use(candidate, iface):
            log.info("Found unused IP (scan): %s", candidate)
            return candidate

    log.error("No unused IP found in %s/%d", base, cidr)
    return None


def _ip_in_use(ip, iface=None, timeout=2):
    """Check if an IP is in use via arping."""
    if not shutil.which("arping"):
        # Fallback to ping
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, check=False, timeout=timeout + 3,
        )
        return r.returncode == 0

    cmd = ["arping", "-c", "1", "-w", str(timeout), ip]
    if iface:
        cmd.extend(["-I", iface])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                          check=False, timeout=timeout + 3)
        return r.returncode == 0 and "bytes from" in r.stdout.lower()
    except subprocess.TimeoutExpired:
        return False

# ── DNS Server Discovery ───────────────────────────────────────

def discover_dns_servers(gateway=None, config=None):
    """Discover DNS servers on the network.

    Priority:
        1. DNS from DHCP sniff (already in config)
        2. Gateway IP (many routers run DNS)
        3. Common internal DNS patterns (x.x.x.1, x.x.x.2, x.x.x.53)
    """
    candidates = []

    if config and config.dns_servers:
        candidates.extend(config.dns_servers)

    if gateway:
        candidates.append(gateway)
        # Common DNS server patterns in the same subnet
        base = gateway.rsplit(".", 1)[0]
        for octet in [1, 2, 10, 53, 100, 254]:
            addr = f"{base}.{octet}"
            if addr not in candidates:
                candidates.append(addr)

    working = []
    for dns_ip in candidates:
        if _test_dns_server(dns_ip):
            working.append(dns_ip)
            log.info("Working DNS server: %s", dns_ip)
            if len(working) >= 2:
                break

    return working


def _test_dns_server(dns_ip, timeout=3):
    """Test if a DNS server responds to queries."""
    try:
        # Build a minimal DNS query for example.com (A record)
        # Using raw socket to avoid needing dig/nslookup
        query = _build_dns_query("example.com")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (dns_ip, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        # Check response has answers (ANCOUNT > 0)
        if len(data) >= 12:
            ancount = struct.unpack("!H", data[6:8])[0]
            return ancount > 0
        return False
    except (socket.error, OSError, struct.error):
        return False


def _build_dns_query(domain):
    """Build a minimal DNS A query packet."""
    import random
    txid = random.randint(0, 65535)
    # Header: ID, flags (standard query), QDCOUNT=1
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    # Question
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"  # root label
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question

# ── Proxy Detection ─────────────────────────────────────────────

def detect_proxy(gateway=None):
    """Detect HTTP proxies via WPAD and common port scanning.

    Returns: (host, port) or (None, None)
    """
    # Method 1: WPAD
    wpad_host = _try_wpad()
    if wpad_host:
        return wpad_host

    # Method 2: Scan common proxy ports on gateway
    if gateway:
        for port in COMMON_PROXY_PORTS:
            if _port_open(gateway, port, timeout=2):
                if _is_http_proxy(gateway, port):
                    log.info("Proxy found: %s:%d", gateway, port)
                    return (gateway, port)

    # Method 3: Scan common proxy ports on .1 and .254 if different from gateway
    if gateway:
        base = gateway.rsplit(".", 1)[0]
        for octet in [1, 254, 2, 10]:
            proxy_ip = f"{base}.{octet}"
            if proxy_ip == gateway:
                continue
            for port in [8080, 3128]:
                if _port_open(proxy_ip, port, timeout=2):
                    if _is_http_proxy(proxy_ip, port):
                        log.info("Proxy found: %s:%d", proxy_ip, port)
                        return (proxy_ip, port)

    return (None, None)


def _try_wpad():
    """Try WPAD auto-discovery."""
    try:
        # Resolve wpad hostname
        import socket as _s
        wpad_ip = _s.gethostbyname("wpad")
        log.info("WPAD resolved to %s", wpad_ip)

        # Fetch wpad.dat
        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((wpad_ip, 80))
        sock.send(b"GET /wpad.dat HTTP/1.0\r\nHost: wpad\r\n\r\n")
        data = sock.recv(4096).decode(errors="replace")
        sock.close()

        # Parse PROXY host:port from wpad.dat
        m = re.search(r"PROXY\s+([\d.]+):(\d+)", data)
        if m:
            host, port = m.group(1), int(m.group(2))
            log.info("WPAD proxy: %s:%d", host, port)
            return (host, port)
    except Exception:
        pass
    return None


def _port_open(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _is_http_proxy(host, port, timeout=3):
    """Verify a port is actually an HTTP proxy by sending a CONNECT."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        resp = s.recv(1024).decode(errors="replace")
        s.close()
        return "200" in resp or "407" in resp  # 407 = proxy auth required (still a proxy)
    except (socket.error, OSError):
        return False

# ── Subnet Brute Force (last resort) ───────────────────────────

def brute_force_subnet(iface, timeout=1800):
    """Brute-force RFC 1918 subnets by ARP-probing gateways.

    This is the last resort — much smarter than the original landnav.py
    approach of setting IPs and bouncing interfaces.  Instead, we ARP
    for gateway IPs directly, which is fast and non-disruptive.

    Returns: NetworkConfig or None
    """
    log.info("Starting subnet brute force (timeout %ds)", timeout)
    deadline = time.time() + timeout

    # Extended subnet list covering more of RFC 1918
    subnets = list(PROBE_SUBNETS)

    # Add the full 192.168.x range
    for third in range(256):
        s = f"192.168.{third}"
        if s not in subnets:
            subnets.append(s)

    # Add 10.x.x ranges
    for second in range(256):
        for third in [0, 1, 10, 100, 254]:
            s = f"10.{second}.{third}"
            if s not in subnets:
                subnets.append(s)
            if time.time() > deadline:
                break
        if time.time() > deadline:
            break

    for subnet in subnets:
        if time.time() > deadline:
            log.warning("Brute force timed out after %ds", timeout)
            return None

        for gw_octet in [1, 254]:
            target = f"{subnet}.{gw_octet}"
            if _ip_in_use(target, iface, timeout=1):
                log.info("Brute force hit: gateway %s", target)
                config = NetworkConfig()
                config.discovery_method = "brute_force"
                config.gateway = target
                config.cidr = 24
                return config

    log.warning("Brute force exhausted all candidates")
    return None

# ── Utility ─────────────────────────────────────────────────────

def _mask_to_cidr(mask):
    """Convert dotted netmask to CIDR prefix length."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 24


def _infer_cidr(ip_list):
    """Guess CIDR prefix from a list of observed IPs."""
    if not ip_list:
        return 24

    # If all IPs share the first 3 octets, it's likely /24
    prefixes = set()
    for ip in ip_list:
        parts = ip.split(".")
        if len(parts) == 4:
            prefixes.add(".".join(parts[:3]))

    if len(prefixes) == 1:
        return 24
    elif len(prefixes) <= 2:
        # Check if they're adjacent — might be /23
        return 23
    else:
        return 16
