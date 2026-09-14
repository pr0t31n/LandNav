#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# landnav_ctl.sh — LandNav process controller
#
# Launches LandNav in its own process group so every child process
# (iodine, meterpreter exec, reverse-shell fork, ip/arp helpers)
# can be killed in one shot.
#
# Usage:
#   landnav_ctl.sh start          # Start in background (new PGID)
#   landnav_ctl.sh stop           # Graceful SIGTERM → SIGKILL
#   landnav_ctl.sh nuke           # Immediate SIGKILL everything
#   landnav_ctl.sh status         # Show running state + tree
#   landnav_ctl.sh restart        # stop + start
#   landnav_ctl.sh run            # Foreground (interactive, Ctrl+C kills all)
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
LANDNAV_PY="$INSTALL_DIR/landnav.py"
PID_FILE="/var/run/landnav.pid"       # Written by landnav.py itself
PGID_FILE="/var/run/landnav.pgid"     # Written by this wrapper
LOG="/var/log/landnav.log"
GRACE_TIMEOUT=5                        # seconds before SIGKILL escalation

# ── helpers ────────────────────────────────────────────────────

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log_msg() { echo "[$(ts)] landnav_ctl: $*" | tee -a "$LOG"; }

get_pgid() {
    [ -f "$PGID_FILE" ] && cat "$PGID_FILE" 2>/dev/null || true
}

get_pid() {
    [ -f "$PID_FILE" ] && cat "$PID_FILE" 2>/dev/null || true
}

pid_alive() {
    local p="$1"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

# Find any python3 landnav.py processes (including children)
find_landnav_pids() {
    pgrep -f 'python3.*landnav\.py' 2>/dev/null || true
}

# Recursively collect all descendants of a PID (children, grandchildren…)
descendants() {
    local parent="$1"
    local kids
    kids=$(pgrep -P "$parent" 2>/dev/null || true)
    for k in $kids; do
        echo "$k"
        descendants "$k"
    done
}

# Kill an entire process group (negative PID = group kill)
kill_group() {
    local sig="$1" pgid="$2"
    [ -z "$pgid" ] && return 1
    kill "-${sig}" -- "-${pgid}" 2>/dev/null || true
}

# Kill stragglers by name after group kill (belt + suspenders)
kill_stragglers() {
    local pids
    pids=$(find_landnav_pids)
    [ -z "$pids" ] && return 0
    log_msg "Killing stragglers: $pids"
    for p in $pids; do
        local desc
        desc=$(descendants "$p")
        kill -9 $p $desc 2>/dev/null || true
    done
}

# ── commands ───────────────────────────────────────────────────

do_start() {
    local pid pgid

    pid=$(get_pid)
    if pid_alive "$pid"; then
        log_msg "Already running (PID $pid)"
        return 0
    fi

    # Clean stale files
    rm -f "$PID_FILE" "$PGID_FILE"

    log_msg "Starting LandNav..."

    # setsid creates a new session + process group.
    # All children (iodine, fork, subprocess) inherit the PGID.
    setsid python3 "$LANDNAV_PY" </dev/null >>"$LOG" 2>&1 &
    pid=$!

    # Give setsid a moment to establish the new session
    sleep 0.3

    # The PGID of the session leader equals its own PID
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    pgid="${pgid:-$pid}"

    echo "$pgid" > "$PGID_FILE"
    # landnav.py writes $PID_FILE itself, but if it hasn't yet, seed it
    [ -f "$PID_FILE" ] || echo "$pid" > "$PID_FILE"

    log_msg "Started (PID $pid, PGID $pgid)"
}

do_stop() {
    local pgid pid waited=0

    pgid=$(get_pgid)
    pid=$(get_pid)

    if [ -z "$pgid" ] && [ -z "$pid" ]; then
        # No files — try by name
        local orphans
        orphans=$(find_landnav_pids)
        if [ -z "$orphans" ]; then
            log_msg "Not running"
            return 0
        fi
        log_msg "No PID/PGID files but found processes: $orphans"
        kill_stragglers
        rm -f "$PID_FILE" "$PGID_FILE"
        log_msg "Stopped (straggler cleanup)"
        return 0
    fi

    log_msg "Stopping LandNav (PID ${pid:-?}, PGID ${pgid:-?})..."

    # Phase 1: SIGTERM the process group
    if [ -n "$pgid" ]; then
        kill_group TERM "$pgid"
    elif [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
    fi

    # Phase 2: wait for graceful shutdown
    while [ $waited -lt $GRACE_TIMEOUT ]; do
        if [ -n "$pid" ] && ! pid_alive "$pid"; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    # Phase 3: SIGKILL if still alive
    if [ -n "$pid" ] && pid_alive "$pid"; then
        log_msg "Grace period expired — escalating to SIGKILL"
        if [ -n "$pgid" ]; then
            kill_group KILL "$pgid"
        else
            kill -9 "$pid" 2>/dev/null || true
        fi
        sleep 1
    fi

    # Phase 4: catch anything that escaped
    kill_stragglers

    rm -f "$PID_FILE" "$PGID_FILE"
    log_msg "Stopped"
}

do_nuke() {
    local pgid pid

    pgid=$(get_pgid)
    pid=$(get_pid)

    log_msg "NUKE — killing everything immediately"

    # Immediate SIGKILL to process group
    if [ -n "$pgid" ]; then
        kill_group KILL "$pgid"
    fi
    if [ -n "$pid" ]; then
        # Also kill all descendants individually
        local desc
        desc=$(descendants "$pid")
        kill -9 $pid $desc 2>/dev/null || true
    fi

    sleep 0.5
    kill_stragglers

    rm -f "$PID_FILE" "$PGID_FILE"
    log_msg "Nuked"
}

do_status() {
    local pid pgid

    pid=$(get_pid)
    pgid=$(get_pgid)

    if pid_alive "$pid"; then
        echo "LandNav is RUNNING"
        echo "  PID:  $pid"
        echo "  PGID: ${pgid:-unknown}"
        echo ""
        echo "Process tree:"
        # Show full tree rooted at the process group
        if [ -n "$pgid" ]; then
            ps -o pid,ppid,pgid,stat,etime,cmd --forest -g "$pgid" 2>/dev/null \
                || ps -o pid,ppid,pgid,stat,etime,cmd -g "$pgid" 2>/dev/null \
                || echo "  (ps -g unavailable — listing by pgrep)"
        fi
        # Fallback: list by name
        local all_pids
        all_pids=$(find_landnav_pids)
        if [ -n "$all_pids" ]; then
            echo ""
            echo "All landnav-related PIDs: $all_pids"
        fi
        return 0
    else
        echo "LandNav is NOT running"
        # Check for orphans
        local orphans
        orphans=$(find_landnav_pids)
        if [ -n "$orphans" ]; then
            echo "  WARNING: orphaned processes found: $orphans"
            echo "  Run: $0 nuke"
        fi
        return 1
    fi
}

do_run() {
    # Foreground mode — Ctrl+C kills everything.
    # We set ourselves as a new process group leader so the trap
    # can kill the whole group.
    local pid pgid

    pid=$(get_pid)
    if pid_alive "$pid"; then
        log_msg "Already running (PID $pid) — stop it first"
        exit 1
    fi

    rm -f "$PID_FILE" "$PGID_FILE"

    log_msg "Starting LandNav (foreground)..."

    # Trap INT/TERM to kill child + its descendants
    trap '_fg_cleanup' INT TERM

    python3 "$LANDNAV_PY" &
    pid=$!
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    pgid="${pgid:-$pid}"
    echo "$pgid" > "$PGID_FILE"

    log_msg "Running (PID $pid, PGID $pgid) — Ctrl+C to stop"
    wait "$pid" 2>/dev/null || true

    rm -f "$PID_FILE" "$PGID_FILE"
    log_msg "Exited"
}

_fg_cleanup() {
    local pgid
    pgid=$(get_pgid)
    echo ""
    log_msg "Caught signal — killing process group"
    if [ -n "$pgid" ]; then
        kill_group TERM "$pgid"
        sleep 2
        kill_group KILL "$pgid" 2>/dev/null || true
    fi
    kill_stragglers
    rm -f "$PID_FILE" "$PGID_FILE"
    log_msg "Cleaned up"
    exit 0
}

# ── dispatch ───────────────────────────────────────────────────

case "${1:-}" in
    start)   do_start   ;;
    stop)    do_stop    ;;
    nuke)    do_nuke    ;;
    status)  do_status  ;;
    restart)
        do_stop
        sleep 1
        do_start
        ;;
    run)     do_run     ;;
    *)
        echo "Usage: $0 {start|stop|nuke|status|restart|run}"
        echo ""
        echo "  start    — Launch LandNav in background (new process group)"
        echo "  stop     — Graceful SIGTERM, then SIGKILL after ${GRACE_TIMEOUT}s"
        echo "  nuke     — Immediate SIGKILL of everything"
        echo "  status   — Show running state and process tree"
        echo "  restart  — stop + start"
        echo "  run      — Foreground (Ctrl+C kills all)"
        exit 1
        ;;
esac
