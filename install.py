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
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

TOOL_NAME = "LandNav"
VERSION = "0.2.1"
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

def install_service(dry_run=False):
    phase("Phase 4: systemd Service")

    if not _has("systemctl"):
        warn("systemd not found — cannot install boot service")
        warn("You'll need to start LandNav manually: python3 landnav.py")
        return

    src = INSTALL_DIR / "systemd" / "landnav.service"
    if not src.exists():
        src = Path(__file__).resolve().parent / "systemd" / "landnav.service"

    dst = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

    if dry_run:
        step(f"Would copy {src} → {dst}")
        step("Would enable and start landnav.service")
        return

    if not src.exists():
        error(f"Service file not found: {src}")
        return

    info(f"Installing service: {dst}")
    shutil.copy2(src, dst)
    dst.chmod(0o644)

    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])
    info(f"Service '{SERVICE_NAME}' enabled — will start on next boot")
    info("To start now: sudo systemctl start landnav")
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
        ("nmap",        _has("nmap")),
        ("responder",   _has("responder") or
                        Path("/usr/share/responder/Responder.py").exists()),
        ("scapy",       _check_import("scapy")),
        ("PyYAML",      _check_import("yaml")),
        ("netifaces",   _check_import("netifaces")),
        ("config.yaml", (INSTALL_DIR / "config.yaml").exists()),
        ("systemd svc", Path(f"/etc/systemd/system/{SERVICE_NAME}.service").exists()),
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

    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    nm_conf = Path("/etc/NetworkManager/conf.d/landnav-unmanage.conf")

    if _has("systemctl"):
        _run(["systemctl", "stop", SERVICE_NAME], check=False, dry_run=dry_run)
        _run(["systemctl", "disable", SERVICE_NAME], check=False, dry_run=dry_run)

    if svc.exists():
        if dry_run:
            step(f"Would remove {svc}")
        else:
            svc.unlink()
            info(f"Removed {svc}")

    if nm_conf.exists():
        if dry_run:
            step(f"Would remove {nm_conf}")
        else:
            nm_conf.unlink()
            info(f"Removed {nm_conf}")
            _run(["systemctl", "restart", "NetworkManager"], check=False)

    if _has("systemctl"):
        _run(["systemctl", "daemon-reload"], check=False, dry_run=dry_run)

    info("LandNav service removed. Files in /opt/pr0t31n/landnav/ left intact.")
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
                        help="(no-op) LandNav has no Go dependencies")
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

    configure_nm_exclusion(os_name, net_backend, dry_run=args.check)
    setup_directories(dry_run=args.check)
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
        print(f"    2. Set iodine password and verify C2 host")
        print(f"    3. Test manually: sudo python3 {INSTALL_DIR}/landnav.py")
        print(f"    4. Deploy:        sudo systemctl start landnav")
        print(f"    5. Reboot test:   sudo reboot")
        print()

if __name__ == "__main__":
    main()
