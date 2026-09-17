#!/usr/bin/env python3
"""LandNav external watchdog.

Checks LandNav health and restarts the service when:
  - LandNav is not running
  - Status heartbeat is stale (>5 minutes)
  - C2 is failed and not attempting reconnection
  - Connected via a backup C2 method but Chisel server is now reachable

Designed to run as a systemd timer (every 2 minutes).
"""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

STATUS_FILE = Path("/var/run/landnav_status.json")
CONFIG_FILE = Path("/opt/pr0t31n/LandNav/config.yaml")
STALE_THRESHOLD = 300  # 5 minutes

def _log(msg):
    subprocess.run(["logger", "-t", "landnav-watchdog", msg],
                   capture_output=True, timeout=5)

def _restart():
    _log("Restarting landnav service")
    subprocess.run(["systemctl", "restart", "landnav"],
                   capture_output=True, timeout=30)

def _service_active():
    r = subprocess.run(["systemctl", "is-active", "landnav"],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip() == "active"

def _load_config():
    try:
        import yaml
    except ImportError:
        return _load_config_fallback()
    try:
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

def _load_config_fallback():
    """Parse just the fields we need without PyYAML."""
    cfg = {"c2": {}, "chisel": {}}
    try:
        text = CONFIG_FILE.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("host:") and "c2" not in cfg["c2"]:
                cfg["c2"]["host"] = stripped.split(":", 1)[1].strip()
            if stripped.startswith("server_port:"):
                try:
                    cfg["chisel"]["server_port"] = int(stripped.split(":")[1].strip())
                except ValueError:
                    pass
            if stripped.startswith("enabled:") and "enabled" not in cfg["chisel"]:
                val = stripped.split(":")[1].strip().lower()
                cfg["chisel"]["enabled"] = val in ("true", "yes", "1")
    except Exception:
        pass
    return cfg

def _chisel_server_reachable(host, port, timeout=5):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (OSError, socket.timeout):
        return False

def main():
    if not _service_active():
        _log("LandNav service not active — restarting")
        _restart()
        return 1

    try:
        status = json.loads(STATUS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        _log("Status file missing or corrupt — restarting")
        _restart()
        return 1

    heartbeat = status.get("last_heartbeat", "")
    if heartbeat:
        try:
            from datetime import datetime
            hb_time = datetime.fromisoformat(heartbeat)
            age = (datetime.now() - hb_time).total_seconds()
            if age > STALE_THRESHOLD:
                _log("Status heartbeat stale (%ds old) — restarting" % int(age))
                _restart()
                return 1
        except (ValueError, TypeError):
            pass

    state = status.get("c2_state", "")
    method = status.get("c2_method")

    if state == "failed":
        _log("C2 state is FAILED — restarting")
        _restart()
        return 1

    if state == "idle":
        _log("C2 state is IDLE (not trying) — restarting")
        _restart()
        return 1

    if state == "connected" and method and method != "chisel":
        cfg = _load_config()
        chisel_cfg = cfg.get("chisel", {})
        if chisel_cfg.get("enabled", False):
            c2_host = cfg.get("c2", {}).get("host", "")
            server_port = chisel_cfg.get("server_port", 8443)
            if c2_host and _chisel_server_reachable(c2_host, server_port):
                _log("Connected via %s but Chisel server is reachable — "
                     "restarting to upgrade" % method)
                _restart()
                return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
