#!/usr/bin/env python3
"""Strip auto_commands.txt for SSH-tunneled ports.

Lightweight helper called by listener.rc on the C2 server (the C2 server)
before starting the Metasploit handler.  Does not import any of
LandNav's implant modules (led, bridge, passive, etc.) so it runs on
machines without Pi-specific dependencies.

Also callable directly:
    python3 prep_handler.py                    # Uses config.yaml in same dir
    python3 prep_handler.py -c /path/to.yaml   # Alternate config
"""

import sys
import yaml
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_AUTO_CMD_PATH = _HERE / "auto_commands.txt"
_DEFAULT_CONFIG = _HERE / "config.yaml"


def generate_auto_commands(cfg):
    tunnel_cfg = cfg.get("ssh_tunnels")
    tunnel_ports = set()
    if tunnel_cfg:
        for fwd in tunnel_cfg.get("forwards", []):
            lp = fwd.get("local_port")
            if lp:
                tunnel_ports.add(int(lp))

    if not _AUTO_CMD_PATH.exists():
        return

    original_lines = _AUTO_CMD_PATH.read_text().splitlines()
    kept = []
    stripped = []
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
            print("  stripped portfwd -l %d (SSH tunnel takes over)" % sp)
    else:
        print("  no portfwd/SSH-tunnel overlap — auto_commands.txt unchanged")


if __name__ == "__main__":
    config_path = _DEFAULT_CONFIG
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg in ("-c", "--config") and i + 1 < len(args):
            config_path = Path(args[i + 1])

    if not config_path.exists():
        # No config → no SSH tunnels → nothing to strip
        sys.exit(0)

    with open(config_path) as f:
        cfg = yaml.safe_load(f) or {}

    generate_auto_commands(cfg)
