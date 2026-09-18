#!/usr/bin/env python3
"""LandNav external watchdog.

Checks LandNav health and restarts the service when:
  - LandNav is not running
  - Status heartbeat is stale (>5 minutes)
  - ALL C2 methods are failed and not attempting reconnection

Designed to run as a systemd timer (every 2 minutes).
"""

import json
import subprocess
import sys
from pathlib import Path

STATUS_FILE = Path("/var/run/landnav_status.json")
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

    # Check aggregate C2 state
    state = status.get("c2_state", "")

    if state == "idle":
        _log("C2 state is IDLE (not trying) — restarting")
        _restart()
        return 1

    # In parallel mode, check if ALL methods are failed
    methods = status.get("methods", {})
    if methods:
        all_failed = all(
            m.get("state") == "failed" for m in methods.values()
        )
        any_connected = any(
            m.get("state") == "connected" for m in methods.values()
        )
        any_attempting = any(
            m.get("state") == "attempting" for m in methods.values()
        )

        if all_failed:
            _log("All C2 methods failed — restarting")
            _restart()
            return 1

        if any_connected or any_attempting:
            return 0
    else:
        # Legacy single-method status format
        if state == "failed":
            _log("C2 state is FAILED — restarting")
            _restart()
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
