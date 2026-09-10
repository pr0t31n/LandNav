#!/usr/bin/env python3
"""Passive network reconnaissance.

Runs as a background thread from Phase 3 onward, continuously
collecting network intelligence with zero active traffic.

Captures:
    - ARP:      IP ↔ MAC mappings, gateway identification
    - DHCP:     New devices, hostnames, lease info
    - DNS:      Internal queries (who resolves what)
    - NetBIOS:  Windows hostnames, workgroup/domain names
    - LLMNR:    Link-local name queries (poisoning candidates)
    - mDNS:     Apple/Linux hostnames, advertised services
    - SSDP:     UPnP device advertisements (IoT, media, routers)
    - 802.1Q:   VLAN tag observation
    - STP:      Bridge topology, root bridge identity

Outputs:
    logs/recon/hosts.json       — live host inventory
    logs/recon/subnets.json     — observed subnets + host counts
    logs/recon/dns_queries.log  — timestamped DNS lookups
    logs/recon/services.json    — mDNS/SSDP advertised services
    logs/recon/targets.txt      — deduplicated CIDR list for scanning
    logs/recon/llmnr.json       — LLMNR/NBT-NS broadcast log (poisoning candidates)
"""

import ipaddress
import json
import logging
import re
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("landnav.passive")

# ── Host Record ─────────────────────────────────────────────────

class HostRecord:
    __slots__ = ("ip", "mac", "hostnames", "sources", "first_seen",
                 "last_seen", "services", "dhcp_hostname", "vendor")

    def __init__(self, ip, mac=None):
        self.ip = ip
        self.mac = mac
        self.hostnames = set()
        self.sources = set()       # arp, dhcp, dns, netbios, mdns, ssdp
        self.first_seen = _now()
        self.last_seen = _now()
        self.services = []
        self.dhcp_hostname = None
        self.vendor = None

    def touch(self, source=None):
        self.last_seen = _now()
        if source:
            self.sources.add(source)

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostnames": sorted(self.hostnames),
            "sources": sorted(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "services": self.services,
            "dhcp_hostname": self.dhcp_hostname,
        }


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Passive Collector ───────────────────────────────────────────

class PassiveCollector:
    """Background passive network intelligence collector."""

    def __init__(self, iface, recon_dir, flush_interval=30):
        self.iface = iface
        self.recon_dir = Path(recon_dir)
        self.flush_interval = flush_interval

        self.hosts = {}            # ip -> HostRecord
        self.subnets = set()       # observed /24 subnets
        self.vlans = set()         # observed 802.1Q VLAN IDs
        self.dns_queries = []      # (timestamp, src_ip, query_name, query_type)
        self.llmnr_queries = []    # (timestamp, src_ip, query_name)
        self.services_list = []    # (ip, service_type, service_name, port)

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer_thread = None
        self._flush_thread = None

        self.recon_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────

    def start(self):
        """Start passive collection in background threads."""
        log.info("Passive recon starting on %s (output: %s)",
                 self.iface, self.recon_dir)
        self._sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="passive-sniff",
        )
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="passive-flush",
        )
        self._sniffer_thread.start()
        self._flush_thread.start()

    def stop(self):
        """Stop collection and flush final state."""
        log.info("Passive recon stopping")
        self._stop.set()
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=5)
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        self._flush_to_disk()

    def get_host_count(self):
        with self._lock:
            return len(self.hosts)

    def get_targets(self):
        """Return deduplicated list of /24 CIDRs."""
        with self._lock:
            return sorted(self.subnets)

    # ── Sniff Loop ──────────────────────────────────────────────

    def _sniff_loop(self):
        """Main packet capture loop using scapy."""
        try:
            from scapy.all import (
                sniff as scapy_sniff, ARP, DHCP, BOOTP, DNS, DNSQR,
                Ether, IP, UDP, Raw, Dot1Q, conf,
            )
            conf.verb = 0

            def _process(pkt):
                if self._stop.is_set():
                    return

                try:
                    with self._lock:
                        # ── 802.1Q VLAN tags ────────────────
                        if Dot1Q in pkt:
                            self.vlans.add(pkt[Dot1Q].vlan)

                        # ── ARP ─────────────────────────────
                        if ARP in pkt:
                            self._process_arp(pkt)

                        # ── DHCP ────────────────────────────
                        if DHCP in pkt:
                            self._process_dhcp(pkt)

                        # ── DNS ─────────────────────────────
                        if DNS in pkt and pkt.haslayer(DNSQR):
                            self._process_dns(pkt)

                        # ── LLMNR (UDP 5355) ────────────────
                        if UDP in pkt and pkt[UDP].dport == 5355:
                            self._process_llmnr(pkt)

                        # ── NetBIOS NS (UDP 137) ────────────
                        if UDP in pkt and pkt[UDP].dport == 137:
                            self._process_netbios(pkt)

                        # ── mDNS (UDP 5353) ─────────────────
                        if UDP in pkt and pkt[UDP].dport == 5353:
                            self._process_mdns(pkt)

                        # ── SSDP (UDP 1900) ─────────────────
                        if UDP in pkt and pkt[UDP].dport == 1900:
                            self._process_ssdp(pkt)

                except Exception as e:
                    log.debug("Packet processing error: %s", e)

            log.info("Passive sniff started on %s", self.iface)
            scapy_sniff(
                iface=self.iface,
                prn=_process,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )

        except ImportError:
            log.error("scapy not available — passive recon disabled")
        except Exception as e:
            log.error("Passive sniff error: %s", e)

    # ── Protocol Processors ─────────────────────────────────────

    def _process_arp(self, pkt):
        from scapy.all import ARP
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip == "0.0.0.0":
            return

        self._record_host(src_ip, mac=src_mac, source="arp")

    def _process_dhcp(self, pkt):
        from scapy.all import DHCP, BOOTP, Ether

        opts = {}
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[opt[0]] = opt[1]

        msg_type = opts.get("message-type", 0)

        # Discover/Request — client info
        if msg_type in (1, 3):
            client_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            hostname = opts.get("hostname")
            if isinstance(hostname, bytes):
                hostname = hostname.decode(errors="replace")
            req_ip = opts.get("requested_addr") or pkt[BOOTP].ciaddr
            if req_ip and req_ip != "0.0.0.0":
                host = self._record_host(req_ip, mac=client_mac, source="dhcp")
                if hostname:
                    host.hostnames.add(hostname)
                    host.dhcp_hostname = hostname

        # Offer/ACK — server + client info
        if msg_type in (2, 5):
            offered = pkt[BOOTP].yiaddr
            if offered and offered != "0.0.0.0":
                self._record_host(offered, source="dhcp")

            router = opts.get("router")
            if router:
                gw = router if isinstance(router, str) else router[0]
                self._record_host(gw, source="dhcp")

            dns_servers = opts.get("name_server")
            if dns_servers:
                if isinstance(dns_servers, str):
                    self._record_host(dns_servers, source="dhcp")
                elif isinstance(dns_servers, (list, tuple)):
                    for ns in dns_servers:
                        self._record_host(ns, source="dhcp")

    def _process_dns(self, pkt):
        from scapy.all import DNS, DNSQR, IP

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors="replace").rstrip(".")
        qtype = pkt[DNSQR].qtype

        # Skip mDNS and LLMNR (handled separately)
        if pkt[IP].dst in ("224.0.0.251", "224.0.0.252"):
            return

        type_map = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
                    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
        qtype_str = type_map.get(qtype, str(qtype))

        self.dns_queries.append((_now(), src_ip, qname, qtype_str))
        self._record_host(src_ip, source="dns")

        # DNS answer section — map names to IPs
        if pkt[DNS].ancount and pkt[DNS].ancount > 0:
            try:
                for i in range(pkt[DNS].ancount):
                    rr = pkt[DNS].an[i] if hasattr(pkt[DNS].an, '__getitem__') else pkt[DNS].an
                    if hasattr(rr, 'rdata') and hasattr(rr, 'type'):
                        if rr.type == 1:  # A record
                            rdata = rr.rdata
                            if isinstance(rdata, str):
                                host = self._record_host(rdata, source="dns")
                                host.hostnames.add(qname)
                    if not hasattr(pkt[DNS].an, '__getitem__'):
                        break
            except Exception:
                pass

    def _process_llmnr(self, pkt):
        from scapy.all import IP, Raw

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        self._record_host(src_ip, source="llmnr")

        # Parse LLMNR query name from raw payload
        if pkt.haslayer(Raw):
            try:
                data = bytes(pkt[Raw].load)
                if len(data) > 12:
                    # LLMNR uses DNS format — skip 12-byte header
                    name_len = data[12]
                    if 0 < name_len < 64 and len(data) > 13 + name_len:
                        name = data[13:13 + name_len].decode(errors="replace")
                        self.llmnr_queries.append((_now(), src_ip, name))
            except Exception:
                pass

    def _process_netbios(self, pkt):
        from scapy.all import IP, Raw

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        self._record_host(src_ip, source="netbios")

        # Parse NetBIOS name from payload
        if pkt.haslayer(Raw):
            try:
                data = bytes(pkt[Raw].load)
                if len(data) > 50:
                    # NetBIOS name is encoded — decode first 16 bytes after header
                    encoded = data[13:45]
                    name = ""
                    for j in range(0, min(len(encoded), 32), 2):
                        if j + 1 < len(encoded):
                            c = ((encoded[j] - 0x41) << 4) | (encoded[j + 1] - 0x41)
                            if 32 <= c <= 126:
                                name += chr(c)
                    name = name.strip()
                    if name:
                        host = self._record_host(src_ip, source="netbios")
                        host.hostnames.add(name)
            except Exception:
                pass

    def _process_mdns(self, pkt):
        from scapy.all import IP, DNS, DNSQR

        if not pkt.haslayer(IP) or not pkt.haslayer(DNS):
            return

        src_ip = pkt[IP].src
        self._record_host(src_ip, source="mdns")

        # Query section
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="replace").rstrip(".")

            # Service type advertisements
            if "_tcp" in qname or "_udp" in qname:
                self.services_list.append((src_ip, qname, "mdns", 0))

            # Hostname from .local queries
            if qname.endswith(".local"):
                hostname = qname.replace(".local", "")
                if hostname and "_" not in hostname:
                    host = self._record_host(src_ip, source="mdns")
                    host.hostnames.add(hostname)

    def _process_ssdp(self, pkt):
        from scapy.all import IP, Raw

        if not pkt.haslayer(IP) or not pkt.haslayer(Raw):
            return

        src_ip = pkt[IP].src
        self._record_host(src_ip, source="ssdp")

        try:
            data = bytes(pkt[Raw].load).decode(errors="replace")

            # Extract service type from ST or NT header
            for header in ("ST:", "NT:"):
                m = re.search(rf"{header}\s*(.+)", data, re.I)
                if m:
                    svc_type = m.group(1).strip()
                    self.services_list.append((src_ip, svc_type, "ssdp", 0))
                    break

            # Extract server info
            m = re.search(r"SERVER:\s*(.+)", data, re.I)
            if m:
                host = self._record_host(src_ip, source="ssdp")
                server_str = m.group(1).strip()
                if server_str not in host.services:
                    host.services.append(server_str)

        except Exception:
            pass

    # ── Host Management ─────────────────────────────────────────

    def _record_host(self, ip, mac=None, source=None):
        """Record or update a host entry. Returns the HostRecord."""
        # Skip non-routable / special addresses
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_multicast or addr.is_loopback or ip == "255.255.255.255":
                return HostRecord(ip)  # throwaway
        except ValueError:
            return HostRecord(ip)

        if ip not in self.hosts:
            self.hosts[ip] = HostRecord(ip, mac)

        host = self.hosts[ip]
        host.touch(source)
        if mac and mac != "ff:ff:ff:ff:ff:ff" and mac != "00:00:00:00:00:00":
            host.mac = mac

        # Track subnet
        subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
        self.subnets.add(subnet)

        return host

    # ── Disk Flush ──────────────────────────────────────────────

    def _flush_loop(self):
        """Periodically write collected data to disk."""
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            if not self._stop.is_set():
                self._flush_to_disk()

    def _flush_to_disk(self):
        """Write all collected data to JSON/text files."""
        with self._lock:
            try:
                # hosts.json
                hosts_data = {ip: h.to_dict() for ip, h in self.hosts.items()}
                self._write_json("hosts.json", hosts_data)

                # subnets.json
                subnet_data = {}
                for subnet in sorted(self.subnets):
                    net = ipaddress.IPv4Network(subnet)
                    count = sum(1 for ip in self.hosts
                               if ipaddress.IPv4Address(ip) in net)
                    subnet_data[subnet] = {
                        "hosts_observed": count,
                        "vlans": sorted(self.vlans) if self.vlans else [],
                    }
                self._write_json("subnets.json", subnet_data)

                # dns_queries.log (append-style)
                dns_path = self.recon_dir / "dns_queries.log"
                with open(dns_path, "w") as f:
                    for ts, src, name, qtype in self.dns_queries[-10000:]:
                        f.write(f"{ts}  {src:>15}  {qtype:<5}  {name}\n")

                # llmnr.json
                llmnr_data = []
                seen_llmnr = {}
                for ts, src, name in self.llmnr_queries:
                    key = f"{src}:{name}"
                    if key not in seen_llmnr:
                        seen_llmnr[key] = {"src_ip": src, "name": name,
                                           "first_seen": ts, "last_seen": ts,
                                           "count": 0}
                    seen_llmnr[key]["last_seen"] = ts
                    seen_llmnr[key]["count"] += 1
                self._write_json("llmnr.json", list(seen_llmnr.values()))

                # services.json
                svc_data = defaultdict(list)
                for ip, svc_type, proto, port in self.services_list:
                    entry = {"type": svc_type, "protocol": proto, "port": port}
                    if entry not in svc_data[ip]:
                        svc_data[ip].append(entry)
                self._write_json("services.json", dict(svc_data))

                # targets.txt — deduplicated CIDRs
                targets_path = self.recon_dir / "targets.txt"
                with open(targets_path, "w") as f:
                    for subnet in sorted(self.subnets):
                        f.write(f"{subnet}\n")

                log.debug("Passive recon flushed: %d hosts, %d subnets, "
                          "%d DNS queries, %d LLMNR queries",
                          len(self.hosts), len(self.subnets),
                          len(self.dns_queries), len(self.llmnr_queries))

            except Exception as e:
                log.warning("Passive recon flush error: %s", e)

    def _write_json(self, filename, data):
        path = self.recon_dir / filename
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
