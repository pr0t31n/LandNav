#!/usr/bin/env python3
"""LandNav installer — multi-platform (optimised for Raspberry Pi / Kali Linux ARM).

Installs system dependencies, Python packages, configures the systemd
boot service, and prepares the config file.

Usage:
    sudo python3 install.py            # Full install
    sudo python3 install.py --check    # Dry run — show what would be done
    sudo python3 install.py --skip-apt # Skip system packages
    sudo python3 install.py --skip-pip # Skip Python packages
    sudo python3 install.py --uninstall # Remove service and config
"""

import argparse
import gzip
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

TOOL_NAME = "LandNav"
VERSION = "0.4.0"
MIN_PYTHON = (3, 10)
INSTALL_DIR = Path("/opt/pr0t31n/landnav")
SERVICE_NAME = "landnav"

# ── ANSI Colours ────────────────────────────────────────────────

_C = {
    "R": "\033[0m", "B": "\033[1m", "G": "\033[32m",
    "Y": "\033[33m", "RD": "\033[31m", "C": "\033[36m",
}

def _p(tag, colour, msg):
    print(f"  {colour}[{tag}]{_C['R']} {msg}")

def info(msg):    _p("+", _C["G"], msg)
def warn(msg):    _p("!", _C["Y"], msg)
def error(msg):   _p("-", _C["RD"], msg)
def step(msg):    _p("*", _C["C"], msg)
def phase(msg):   print(f"\n{_C['B']}{'═' * 60}\n  {msg}\n{'═' * 60}{_C['R']}")

def _run(cmd, check=True, dry_run=False):
    display = " ".join(cmd) if isinstance(cmd, list) else cmd
    step(f"→ {display}")
    if dry_run:
        return None
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)

def _has(binary):
    return shutil.which(binary) is not None

# ── OS Detection ────────────────────────────────────────────────

def detect_os():
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s != "linux":
        return s
    try:
        osrel = Path("/etc/os-release").read_text().lower()
        if "kali" in osrel:
            return "kali"
        if "raspbian" in osrel or "raspberry" in osrel:
            return "raspbian"
        if "ubuntu" in osrel or "debian" in osrel:
            return "debian"
    except FileNotFoundError:
        pass
    return "linux"

# ── Networking Backend Detection ────────────────────────────────

def detect_net_backend():
    """Detect what manages networking on this system."""
    if _has("nmcli"):
        try:
            r = subprocess.run(["nmcli", "-t", "-f", "RUNNING", "general"],
                             capture_output=True, text=True, check=False, timeout=5)
            if "running" in r.stdout.lower():
                return "networkmanager"
        except Exception:
            pass
    if _has("netplan") and any(Path("/etc/netplan").glob("*.yaml")):
        return "netplan"
    if Path("/etc/network/interfaces").exists():
        return "interfaces"
    return "unknown"

# ── Phase: System Packages ──────────────────────────────────────

# Required system packages
APT_PACKAGES = [
    "bridge-utils",     # brctl (bridge management)
    "ebtables",         # Layer 2 MAC rewriting
    "tcpdump",          # Packet capture
    "arping",           # ARP probing
    "iodine",           # DNS tunneling
    "iproute2",         # ip command suite
    "nmap",             # Network scanning (used by discovery)
    "dnsutils",         # nslookup, dig
    "net-tools",        # ifconfig, route (legacy compat)
    "curl",             # HTTP testing
    "python3-pip",      # pip
    "python3-scapy",    # scapy (prefer system package on Pi)
    "responder",        # LLMNR/NBT-NS/WPAD analyzer
]

BREW_PACKAGES = [
    "iproute2mac",      # ip command on macOS (limited)
    "nmap",
    "iodine",
]

def install_system_deps(os_name, dry_run=False):
    phase("Phase 1: System Packages")

    if os_name in ("kali", "raspbian", "debian"):
        if not _has("apt-get"):
            error("apt-get not found")
            return
        _run(["apt-get", "update", "-qq"], dry_run=dry_run, check=False)
        _run(["apt-get", "install", "-y", "--no-install-recommends"] + APT_PACKAGES,
             dry_run=dry_run, check=False)

        # Responder may not be in apt on all distros — check if installed
        if not dry_run and not _has("responder"):
            # Try installing from Kali repo or clone from GitHub
            info("Responder not in apt — checking /usr/share/responder/")
            if not Path("/usr/share/responder/Responder.py").exists():
                warn("Responder not found — install manually from "
                     "https://github.com/lgandx/Responder or apt install responder")

    elif os_name == "macos":
        if not _has("brew"):
            warn("Homebrew not found — install from https://brew.sh")
            return
        for pkg in BREW_PACKAGES:
            _run(["brew", "install", pkg], dry_run=dry_run, check=False)
        warn("macOS: bridge/ebtables/arping/responder not available — "
             "LandNav bridge mode and Responder require Linux")

    else:
        warn(f"Unknown OS '{os_name}' — install these manually: "
             f"{', '.join(APT_PACKAGES)}")

# ── Phase: Python Packages ──────────────────────────────────────

def install_pip_deps(dry_run=False):
    phase("Phase 2: Python Packages")

    req_file = INSTALL_DIR / "requirements.txt"
    if not req_file.exists():
        req_file = Path(__file__).resolve().parent / "requirements.txt"

    if not req_file.exists():
        warn("requirements.txt not found — skipping pip install")
        return

    _run([sys.executable, "-m", "pip", "install",
          "--break-system-packages", "-r", str(req_file)],
         dry_run=dry_run, check=False)

# ── Phase: Chisel Binary ───────────────────────────────────────

# Map platform.machine() output to chisel release architecture names
_ARCH_MAP = {
    "aarch64":  "arm64",
    "arm64":    "arm64",
    "x86_64":   "amd64",
    "amd64":    "amd64",
    "armv7l":   "armv7",
    "armv6l":   "armv6",
}

# Chisel release version to install — pin to a known-good version
CHISEL_VERSION = "1.10.1"

def install_chisel(dry_run=False):
    """Download the chisel binary from GitHub releases.

    Architecture-aware: detects arm64 (Pi 4/5), amd64 (c2-server/x86),
    armv7/v6 (older Pis).  Idempotent — skips if chisel is already in
    PATH at the correct version.
    """
    phase("Phase 2b: Chisel Binary")

    if _has("chisel"):
        # Check version
        try:
            r = subprocess.run(["chisel", "--version"], capture_output=True,
                               text=True, check=False, timeout=5)
            ver = r.stdout.strip() + r.stderr.strip()
            if CHISEL_VERSION in ver:
                info(f"chisel {CHISEL_VERSION} already installed ✓")
                return
            else:
                info(f"chisel found but version mismatch ({ver.strip()}) — upgrading")
        except Exception:
            info("chisel found but version check failed — upgrading")

    machine = platform.machine()
    arch = _ARCH_MAP.get(machine)
    if not arch:
        warn(f"Unknown architecture '{machine}' — cannot download chisel")
        warn("Install manually: go install github.com/jpillora/chisel@latest")
        warn("  Or download from https://github.com/jpillora/chisel/releases")
        return

    sysname = platform.system().lower()
    if sysname == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"

    filename = f"chisel_{CHISEL_VERSION}_{os_name}_{arch}.gz"
    url = (f"https://github.com/jpillora/chisel/releases/download/"
           f"v{CHISEL_VERSION}/{filename}")

    dest = Path("/usr/local/bin/chisel")

    if dry_run:
        step(f"Would download {url}")
        step(f"Would install to {dest}")
        return

    info(f"Downloading chisel {CHISEL_VERSION} for {os_name}/{arch}")
    step(f"→ {url}")

    try:
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        req = urllib.request.Request(url, headers={"User-Agent": "LandNav-Installer"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            tmp_path.write_bytes(resp.read())

        # Decompress .gz → binary
        with gzip.open(tmp_path, "rb") as gz_in:
            dest.write_bytes(gz_in.read())

        dest.chmod(0o755)
        tmp_path.unlink(missing_ok=True)

        # Verify
        r = subprocess.run([str(dest), "--version"], capture_output=True,
                           text=True, check=False, timeout=5)
        ver = (r.stdout.strip() + r.stderr.strip()).strip()
        info(f"chisel installed: {dest} ({ver})")

    except Exception as e:
        error(f"Failed to download chisel: {e}")
        warn("Install manually: go install github.com/jpillora/chisel@latest")
        warn("  Or download from https://github.com/jpillora/chisel/releases")
        # Clean up partial download
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

# ── Phase: SSH Tunnel Keys ─────────────────────────────────────

def setup_ssh_keys(dry_run=False):
    """Generate the SSH tunnel keypair if it doesn't exist."""
    phase("Phase 2c: SSH Tunnel Keys")

    keys_dir = INSTALL_DIR / "keys"
    key_path = keys_dir / "tunnel_key"

    if key_path.exists():
        info(f"SSH tunnel key already exists: {key_path}")
        if not dry_run:
            key_path.chmod(0o600)
        return

    if dry_run:
        step(f"Would generate ed25519 keypair at {key_path}")
        return

    keys_dir.mkdir(parents=True, exist_ok=True)
    info("Generating SSH tunnel keypair (ed25519)...")

    hostname = platform.node() or "landnav"
    _run(["ssh-keygen", "-t", "ed25519", "-f", str(key_path),
          "-N", "", "-C", f"landnav-tunnel@{hostname}"])
    key_path.chmod(0o600)
    info(f"Generated: {key_path} + {key_path}.pub")
    warn("Copy keys/ directory to the implant device (beretta)")
    warn("Add the public key to c2-server's authorized_keys:")
    warn(f"  cat {key_path}.pub >> ~/.ssh/authorized_keys")

# ── Phase: NetworkManager Exclusion ─────────────────────────────

def configure_nm_exclusion(os_name, net_backend, dry_run=False):
    """Tell NetworkManager to leave ethernet interfaces alone.

    LandNav manages its own interfaces.  If NM is running, we need
    to either unmanage the interfaces or stop NM entirely.
    """
    phase("Phase 3: Networking Backend Configuration")

    info(f"Detected networking backend: {net_backend}")

    if net_backend != "networkmanager":
        info("Not NetworkManager — no exclusion needed")
        return

    nm_conf = Path("/etc/NetworkManager/conf.d/landnav-unmanage.conf")
    content = """\
# LandNav — prevent NetworkManager from managing ethernet interfaces.
# LandNav creates its own bridge and manages IP configuration.
# Remove this file and restart NM to restore normal behaviour.
[keyfile]
unmanaged-devices=interface-name:eth*;interface-name:enx*;interface-name:usb*;interface-name:br0
"""

    if dry_run:
        step(f"Would write {nm_conf}")
        return

    info(f"Writing NM exclusion: {nm_conf}")
    nm_conf.parent.mkdir(parents=True, exist_ok=True)
    nm_conf.write_text(content)

    # Restart NM to pick up the change
    _run(["systemctl", "restart", "NetworkManager"], check=False)
    info("NetworkManager restarted with LandNav exclusions")

# ── Phase: systemd Service ──────────────────────────────────────

def _find_unit(name):
    """Locate a systemd unit file in the repo (systemd/ subdir or repo root)."""
    for base in (INSTALL_DIR, Path(__file__).resolve().parent):
        for sub in (base / "systemd" / name, base / name):
            if sub.exists():
                return sub
    return None

def install_service(dry_run=False):
    phase("Phase 4: systemd Service + Watchdog")

    if not _has("systemctl"):
        warn("systemd not found — cannot install boot service")
        warn("You'll need to start LandNav manually: python3 landnav.py")
        return

    units = [
        ("landnav.service",            True),
        ("landnav-watchdog.service",   False),
        ("landnav-watchdog.timer",     False),
    ]

    if dry_run:
        for name, _ in units:
            step(f"Would install /etc/systemd/system/{name}")
        step("Would enable and start landnav.service + landnav-watchdog.timer")
        return

    installed = []
    for name, _ in units:
        src = _find_unit(name)
        if not src:
            error(f"Unit file not found: {name}")
            continue
        dst = Path(f"/etc/systemd/system/{name}")
        info(f"Installing: {dst}")
        shutil.copy2(src, dst)
        dst.chmod(0o644)
        installed.append(name)

    if not installed:
        error("No unit files installed — cannot continue")
        return

    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", SERVICE_NAME])
    _run(["systemctl", "enable", "--now", "landnav-watchdog.timer"])
    info("landnav.service enabled and started")
    info("landnav-watchdog.timer enabled and started (checks every 2 minutes)")
    info("To check status: sudo systemctl status landnav")
    info("To view logs: sudo journalctl -u landnav -f")

# ── Phase: Config File ──────────────────────────────────────────

def setup_config(dry_run=False):
    phase("Phase 5: Configuration")

    config_file = INSTALL_DIR / "config.yaml"
    example_file = INSTALL_DIR / "config.yaml.example"

    if not example_file.exists():
        example_file = Path(__file__).resolve().parent / "config.yaml.example"

    if config_file.exists():
        info(f"Config already exists: {config_file}")
        info("Edit it before deploying: sudo nano config.yaml")
        return

    if dry_run:
        step(f"Would copy {example_file} → {config_file}")
        return

    if example_file.exists():
        shutil.copy2(example_file, config_file)
        config_file.chmod(0o600)  # Only root can read (contains C2 info)
        info(f"Config created: {config_file}")
        warn("IMPORTANT: Edit config.yaml before deploying!")
        warn("  At minimum, set the iodine password:")
        warn(f"  sudo nano {config_file}")
    else:
        warn(f"Example config not found: {example_file}")

# ── Phase: Directories and Permissions ──────────────────────────

def setup_directories(dry_run=False):
    phase("Phase 6: Directories and Permissions")

    dirs = [
        INSTALL_DIR / "logs",
        INSTALL_DIR / "logs" / "recon",
        INSTALL_DIR / "logs" / "recon" / "responder",
    ]

    for d in dirs:
        if dry_run:
            step(f"Would create {d}")
        else:
            d.mkdir(parents=True, exist_ok=True)
            info(f"Created: {d}")

    # Ensure landnav.py is executable
    main_py = INSTALL_DIR / "landnav.py"
    if main_py.exists() and not dry_run:
        main_py.chmod(0o755)

# ── Phase: Verification ────────────────────────────────────────

def verify_install():
    phase("Verification")

    checks = [
        ("python3",     _has("python3")),
        ("ip",          _has("ip")),
        ("brctl",       _has("brctl")),
        ("ebtables",    _has("ebtables")),
        ("tcpdump",     _has("tcpdump")),
        ("arping",      _has("arping")),
        ("iodine",      _has("iodine")),
        ("chisel",      _has("chisel")),
        ("ssh-keygen",  _has("ssh-keygen")),
        ("nmap",        _has("nmap")),
        ("responder",   _has("responder") or
                        Path("/usr/share/responder/Responder.py").exists()),
        ("scapy",       _check_import("scapy")),
        ("PyYAML",      _check_import("yaml")),
        ("netifaces",   _check_import("netifaces")),
        ("tunnel key",  (INSTALL_DIR / "keys" / "tunnel_key").exists()),
        ("config.yaml", (INSTALL_DIR / "config.yaml").exists()),
        ("systemd svc", Path(f"/etc/systemd/system/{SERVICE_NAME}.service").exists()),
        ("watchdog timer", Path("/etc/systemd/system/landnav-watchdog.timer").exists()),
    ]

    all_ok = True
    for name, ok in checks:
        if ok:
            info(f"✓ {name}")
        else:
            warn(f"✗ {name}")
            all_ok = False

    return all_ok

def _check_import(module):
    try:
        __import__(module)
        return True
    except ImportError:
        return False

# ── Uninstall ───────────────────────────────────────────────────

def uninstall(dry_run=False):
    phase("Uninstalling LandNav")

    unit_files = [
        Path(f"/etc/systemd/system/{SERVICE_NAME}.service"),
        Path("/etc/systemd/system/landnav-watchdog.service"),
        Path("/etc/systemd/system/landnav-watchdog.timer"),
    ]
    nm_conf = Path("/etc/NetworkManager/conf.d/landnav-unmanage.conf")

    if _has("systemctl"):
        _run(["systemctl", "stop", "landnav-watchdog.timer"], check=False, dry_run=dry_run)
        _run(["systemctl", "disable", "landnav-watchdog.timer"], check=False, dry_run=dry_run)
        _run(["systemctl", "stop", SERVICE_NAME], check=False, dry_run=dry_run)
        _run(["systemctl", "disable", SERVICE_NAME], check=False, dry_run=dry_run)

    for uf in unit_files:
        if uf.exists():
            if dry_run:
                step(f"Would remove {uf}")
            else:
                uf.unlink()
                info(f"Removed {uf}")

    if nm_conf.exists():
        if dry_run:
            step(f"Would remove {nm_conf}")
        else:
            nm_conf.unlink()
            info(f"Removed {nm_conf}")
            _run(["systemctl", "restart", "NetworkManager"], check=False)

    if _has("systemctl"):
        _run(["systemctl", "daemon-reload"], check=False, dry_run=dry_run)

    info("LandNav services removed. Files in /opt/pr0t31n/landnav/ left intact.")
    info("To fully remove: sudo rm -rf /opt/pr0t31n/landnav/")

# ── Main ────────────────────────────────────────────────────────

def main():
    if sys.version_info < MIN_PYTHON:
        error(f"Python {'.'.join(map(str, MIN_PYTHON))}+ required "
              f"(found {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} — Installer",
    )
    parser.add_argument("--check", action="store_true",
                        help="Dry run — show what would be done")
    parser.add_argument("--skip-apt", action="store_true",
                        help="Skip system package installation")
    parser.add_argument("--skip-pip", action="store_true",
                        help="Skip Python package installation")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove systemd service and NM config")
    parser.add_argument("--skip-go", action="store_true",
                        help="Skip chisel binary download")
    parser.add_argument("--skip-git", action="store_true",
                        help="(no-op) LandNav has no git tool dependencies")
    args = parser.parse_args()

    print(f"\n{_C['B']}{'═' * 60}")
    print(f"  {TOOL_NAME} v{VERSION} — {'Dry Run' if args.check else 'Installation'}")
    print(f"{'═' * 60}{_C['R']}")

    if args.uninstall:
        uninstall(dry_run=args.check)
        return

    if os.geteuid() != 0 and not args.check:
        error("This installer must be run as root: sudo python3 install.py")
        sys.exit(1)

    os_name = detect_os()
    net_backend = detect_net_backend()
    info(f"Platform: {os_name} ({platform.machine()})")
    info(f"Python: {sys.version.split()[0]}")
    info(f"Networking: {net_backend}")

    if not args.skip_apt:
        install_system_deps(os_name, dry_run=args.check)

    if not args.skip_pip:
        install_pip_deps(dry_run=args.check)

    if not args.skip_go:
        install_chisel(dry_run=args.check)

    configure_nm_exclusion(os_name, net_backend, dry_run=args.check)
    setup_directories(dry_run=args.check)
    setup_ssh_keys(dry_run=args.check)
    setup_config(dry_run=args.check)
    install_service(dry_run=args.check)

    if not args.check:
        all_ok = verify_install()
        print()
        if all_ok:
            info(f"{_C['B']}{TOOL_NAME} installed successfully.{_C['R']}")
        else:
            warn(f"{TOOL_NAME} installed with warnings — check above.")

        print(f"\n  Next steps:")
        print(f"    1. Edit config:   sudo nano {INSTALL_DIR}/config.yaml")
        print(f"    2. Set chisel auth, iodine password, and verify C2 host")
        print(f"    3. Copy keys/ directory to beretta (the implant device)")
        print(f"    4. Test manually: sudo python3 {INSTALL_DIR}/landnav.py")
        print(f"    5. Deploy:        sudo systemctl start landnav")
        print(f"    6. Reboot test:   sudo reboot")
        print()

if __name__ == "__main__":
    main()
