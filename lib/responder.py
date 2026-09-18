#!/usr/bin/env python3
"""Responder analyzer mode integration.

Runs Responder with -A (analyze) flag — passive observation of
LLMNR/NBT-NS/mDNS/WPAD broadcast traffic without poisoning.

Collects:
    - Which hosts broadcast LLMNR/NBT-NS queries (poisoning targets)
    - What names they're trying to resolve (stale DNS, typos, nonexistent shares)
    - WPAD requests (proxy auto-config poisoning candidates)
    - HTTP/SMB/SQL authentication attempts observed passively

All output is logged to the recon directory. The operator can
review this intel via C2 and decide whether to switch Responder
to active mode.
"""

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("landnav.responder")

# Common Responder install locations
RESPONDER_PATHS = [
    "/usr/share/responder/Responder.py",
    "/opt/responder/Responder.py",
    "/usr/bin/responder",
    "/usr/local/bin/responder",
]

MAX_RESTARTS = 5
RESTART_BACKOFF_BASE = 10


class ResponderAnalyzer:
    """Runs Responder in analyze-only mode as a background process."""

    def __init__(self, iface, recon_dir, responder_path=None):
        self.iface = iface
        self.recon_dir = Path(recon_dir)
        self.responder_path = responder_path or self._find_responder()
        self._process = None
        self._monitor_thread = None
        self._stop = threading.Event()
        self._restart_count = 0

        self.recon_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────

    def start(self):
        """Start Responder in analyze mode."""
        if not self.responder_path:
            log.warning("Responder not found — analyzer mode unavailable")
            return False

        log.info("Starting Responder in ANALYZE mode on %s", self.iface)
        log.info("  Path: %s", self.responder_path)
        log.info("  Output: %s", self.recon_dir / "responder")

        responder_log_dir = self.recon_dir / "responder"
        responder_log_dir.mkdir(parents=True, exist_ok=True)

        if not self._start_process(responder_log_dir):
            return False

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="responder-monitor",
        )
        self._monitor_thread.start()

        return True

    def stop(self):
        """Stop the Responder process."""
        self._stop.set()

        if self._process and self._process.poll() is None:
            log.info("Stopping Responder (PID %d)", self._process.pid)
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
            log.info("Responder stopped")

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

        # Parse and consolidate Responder's logs
        self._consolidate_logs()

    def is_running(self):
        return self._process is not None and self._process.poll() is None

    # ── Process Lifecycle ──────────────────────────────────────

    def _start_process(self, log_dir):
        """Launch the Responder subprocess. Returns True on success."""
        cmd = self._build_command()
        log.info("  Command: %s", " ".join(cmd))

        try:
            stdout_log = open(log_dir / "responder_stdout.log", "a")
            stderr_log = open(log_dir / "responder_stderr.log", "a")

            env = os.environ.copy()

            self._process = subprocess.Popen(
                cmd,
                stdout=stdout_log,
                stderr=stderr_log,
                env=env,
                cwd=str(Path(self.responder_path).parent),
            )

            log.info("Responder analyzer started (PID %d)", self._process.pid)
            return True

        except Exception as e:
            log.error("Failed to start Responder: %s", e)
            return False

    # ── Command Builder ─────────────────────────────────────────

    def _build_command(self):
        """Build the Responder command line for analyze mode."""
        cmd = []

        # Determine how to invoke
        if self.responder_path.endswith(".py"):
            cmd = ["python3", self.responder_path]
        else:
            cmd = [self.responder_path]

        # Core flags
        cmd.extend([
            "-I", self.iface,   # Interface
            "-A",               # Analyze mode — NO POISONING
        ])

        return cmd

    # ── Monitor ─────────────────────────────────────────────────

    def _monitor_loop(self):
        """Monitor Responder process health and restart if needed."""
        while not self._stop.is_set():
            self._stop.wait(15)
            if self._stop.is_set():
                break

            if self._process and self._process.poll() is not None:
                exit_code = self._process.returncode
                self._restart_count += 1

                if self._restart_count > MAX_RESTARTS:
                    log.error("Responder exceeded %d restarts — giving up",
                              MAX_RESTARTS)
                    break

                delay = min(RESTART_BACKOFF_BASE * self._restart_count, 120)
                log.warning("Responder exited with code %d — restart %d/%d "
                            "in %ds", exit_code, self._restart_count,
                            MAX_RESTARTS, delay)
                self._stop.wait(delay)
                if self._stop.is_set():
                    break

                log_dir = self.recon_dir / "responder"
                self._start_process(log_dir)

    # ── Log Consolidation ───────────────────────────────────────

    def _consolidate_logs(self):
        """Parse Responder's log files into a structured summary.

        Responder writes to its own logs/ directory. We parse those
        into a consolidated JSON summary.
        """
        responder_dir = Path(self.responder_path).parent / "logs"
        output = self.recon_dir / "responder"

        if not responder_dir.exists():
            return

        summary = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": "analyze",
            "interface": self.iface,
            "hashes": [],
            "poisoning_candidates": [],
            "wpad_requests": [],
        }

        try:
            # Parse Responder's log files for captured data
            for log_file in responder_dir.glob("*.txt"):
                content = log_file.read_text(errors="replace")

                # Look for hash captures (even in analyze mode, Responder logs
                # hashes from traffic it observes)
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # NTLMv2 hash format
                    if ":::" in line and ("NTLMv" in str(log_file) or
                                          "NTLM" in line):
                        summary["hashes"].append({
                            "hash": line,
                            "source_file": log_file.name,
                        })

            # Parse stdout log for observed queries
            stdout_log = output / "responder_stdout.log"
            if stdout_log.exists():
                content = stdout_log.read_text(errors="replace")
                for line in content.splitlines():
                    # LLMNR/NBT-NS queries
                    m = re.search(
                        r"\[(\w+)\].*?from:\s*(\d+\.\d+\.\d+\.\d+).*?for:\s*(.+)",
                        line, re.I,
                    )
                    if m:
                        proto, src, name = m.groups()
                        summary["poisoning_candidates"].append({
                            "protocol": proto.strip(),
                            "source_ip": src.strip(),
                            "queried_name": name.strip(),
                        })

                    # WPAD requests
                    if "WPAD" in line.upper():
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if m:
                            summary["wpad_requests"].append({
                                "source_ip": m.group(1),
                                "raw_line": line.strip(),
                            })

            # Write consolidated summary
            summary_path = output / "responder_summary.json"
            import json
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)

            log.info("Responder summary: %d hashes, %d poisoning candidates, "
                     "%d WPAD requests",
                     len(summary["hashes"]),
                     len(summary["poisoning_candidates"]),
                     len(summary["wpad_requests"]))

            # Copy relevant Responder logs to our recon directory
            for log_file in responder_dir.glob("*.txt"):
                dest = output / log_file.name
                if not dest.exists():
                    shutil.copy2(log_file, dest)

        except Exception as e:
            log.warning("Responder log consolidation error: %s", e)

    # ── Responder Discovery ─────────────────────────────────────

    def _find_responder(self):
        """Locate the Responder binary/script."""
        # Check PATH first
        which = shutil.which("responder")
        if which:
            return which

        # Check known locations
        for path in RESPONDER_PATHS:
            if Path(path).exists():
                return path

        return None
