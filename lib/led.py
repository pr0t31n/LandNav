#!/usr/bin/env python3
"""LED status controller for Raspberry Pi ACT LED.

Controls the green ACT LED on the Pi 4B via sysfs to provide
visual state feedback without requiring screen or network access.

Patterns:
    BOOTING      — slow heartbeat (0.5 Hz)
    BRIDGE_UP    — steady slow blink (1 Hz)
    DISCOVERY    — double blink, pause
    NETWORK_UP   — fast blink (2 Hz)
    C2_ATTEMPT   — triple blink, pause
    C2_CONNECTED — solid on
    ERROR        — SOS (... --- ...)
    SHUTDOWN     — rapid blinks slowing to off
"""

import threading
import time
from pathlib import Path


# ── LED States ──────────────────────────────────────────────────

BOOTING      = "booting"
BRIDGE_UP    = "bridge_up"
DISCOVERY    = "discovery"
NETWORK_UP   = "network_up"
C2_ATTEMPT   = "c2_attempt"
C2_CONNECTED = "c2_connected"
ERROR        = "error"
SHUTDOWN     = "shutdown"
OFF          = "off"

# ── Pattern Definitions (on_ms, off_ms) sequences ──────────────

_PATTERNS = {
    BOOTING:      [(800, 800)],
    BRIDGE_UP:    [(500, 500)],
    DISCOVERY:    [(150, 150), (150, 600)],
    NETWORK_UP:   [(250, 250)],
    C2_ATTEMPT:   [(150, 150), (150, 150), (150, 600)],
    C2_CONNECTED: [(0, 0)],        # solid on, special-cased
    ERROR:        [                 # SOS: ... --- ...
        (150, 150), (150, 150), (150, 400),   # S: ...
        (400, 150), (400, 150), (400, 400),   # O: ---
        (150, 150), (150, 150), (150, 800),   # S: ...
    ],
    SHUTDOWN:     [
        (50, 50), (50, 100), (50, 150), (50, 200),
        (50, 300), (50, 500), (50, 1000),
    ],
    OFF:          [(0, 0)],        # solid off, special-cased
}


class LedController:
    """Non-blocking LED pattern controller running in a daemon thread."""

    def __init__(self, led_path="/sys/class/leds/ACT", enabled=True):
        self._led_path = Path(led_path)
        self._enabled = enabled and self._led_path.exists()
        self._state = OFF
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._change = threading.Event()
        self._thread = None

        if self._enabled:
            self._take_control()
            self._start_thread()

    # ── Public API ──────────────────────────────────────────────

    def set_state(self, state):
        """Change LED pattern. Thread-safe."""
        if state == self._state:
            return
        with self._lock:
            self._state = state
        self._change.set()

    def stop(self):
        """Shut down the LED thread and release control."""
        self._stop.set()
        self._change.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self._enabled:
            self._release_control()

    @property
    def state(self):
        return self._state

    # ── sysfs Control ───────────────────────────────────────────

    def _take_control(self):
        """Set trigger to 'none' for manual brightness control."""
        try:
            (self._led_path / "trigger").write_text("none")
        except (PermissionError, OSError):
            self._enabled = False

    def _release_control(self):
        """Restore default trigger."""
        try:
            (self._led_path / "trigger").write_text("mmc0")
            (self._led_path / "brightness").write_text("1")
        except (PermissionError, OSError):
            pass

    def _led_on(self):
        try:
            (self._led_path / "brightness").write_text("1")
        except (PermissionError, OSError):
            pass

    def _led_off(self):
        try:
            (self._led_path / "brightness").write_text("0")
        except (PermissionError, OSError):
            pass

    # ── Pattern Thread ──────────────────────────────────────────

    def _start_thread(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                state = self._state
            self._change.clear()

            if state == C2_CONNECTED:
                self._led_on()
                self._change.wait()
                continue

            if state == OFF:
                self._led_off()
                self._change.wait()
                continue

            pattern = _PATTERNS.get(state, _PATTERNS[ERROR])

            if state == SHUTDOWN:
                # Play once, then stay off
                for on_ms, off_ms in pattern:
                    if self._stop.is_set() or self._change.is_set():
                        break
                    self._led_on()
                    time.sleep(on_ms / 1000.0)
                    self._led_off()
                    time.sleep(off_ms / 1000.0)
                self._led_off()
                self._change.wait()
                continue

            # Repeat pattern until state changes
            while not self._stop.is_set() and not self._change.is_set():
                for on_ms, off_ms in pattern:
                    if self._stop.is_set() or self._change.is_set():
                        break
                    self._led_on()
                    time.sleep(on_ms / 1000.0)
                    self._led_off()
                    time.sleep(off_ms / 1000.0)

        self._led_off()


# ── Convenience singleton ───────────────────────────────────────

_instance = None

def init(led_path="/sys/class/leds/ACT", enabled=True):
    global _instance
    _instance = LedController(led_path, enabled)
    return _instance

def set_state(state):
    if _instance:
        _instance.set_state(state)

def stop():
    if _instance:
        _instance.stop()
