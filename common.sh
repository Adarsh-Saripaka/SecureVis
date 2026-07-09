#!/usr/bin/env python3
"""
securevis_common.py — shared event bus for SecureVis.

Previously the live dashboard (collector.py + gui.py) and the sandbox
script (securevis-sandbox.sh) each kept their own separate event/state
files with no communication between them: a honeypot trip during a
sandbox session never showed up in the live dashboard, and the
dashboard's process risk scoring never fed into the sandbox's forensic
report.

This module is the single place both sides read and write events, with
file locking so concurrent writers (a Python process and a Bash script
both writing at once) don't corrupt the log.

Usage from Python:
    from securevis_common import emit_event, read_events
    emit_event("HIGH_CPU_ANOMALY", detail="pid=1234,name=foo", source="collector")

Usage from Bash (via CLI mode):
    python3 securevis_common.py emit HONEYPOT_ACCESS "ACCESS:/merged/id_rsa" sandbox
"""
import json
import os
import sys
import time
import fcntl

EVENTS_FILE = "/tmp/securevis_events.json"
MAX_EVENTS = 500  # keep the log bounded so it doesn't grow forever

# MITRE ATT&CK mapping shared by the forensic report generator and the
# live GUI, so both show the same technique tags for the same event type.
MITRE_MAP = {
    "HONEYPOT_ACCESS":    ("T1083", "File and Directory Discovery"),
    "RWX_MEMORY_REGION":  ("T1055", "Process Injection"),
    "HIGH_CPU_ANOMALY":   ("T1496", "Resource Hijacking"),
    "UNEXPECTED_CHILD":   ("T1059", "Command and Scripting Interpreter"),
    "MASS_FILE_ACCESS":   ("T1005", "Data from Local System"),
    "WEBCAM_SNAPSHOT":    ("T1113", "Screen Capture"),
    "AUTH_FAILURE":       ("T1110", "Brute Force"),
    "SANDBOX_START":      ("--", "Session start"),
    "SANDBOX_END":        ("--", "Session end"),
    "SETUP_FAILURE":      ("--", "Sandbox setup error"),
}

HIGH_SEVERITY = {"HONEYPOT_ACCESS", "RWX_MEMORY_REGION", "AUTH_FAILURE"}


def _ensure_file():
    if not os.path.exists(EVENTS_FILE):
        # 'x' mode avoids a race where two processes both see "missing"
        # and both try to create it; if we lose that race, that's fine,
        # the other writer's file is just as valid.
        try:
            with open(EVENTS_FILE, "x") as f:
                f.write("[]")
        except FileExistsError:
            pass


def _load_locked(f):
    f.seek(0)
    raw = f.read()
    if not raw.strip():
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Corrupted by a partial write from an old, non-locked writer.
        # Don't crash the whole event bus over it — start fresh but say so.
        sys.stderr.write("[securevis_common] events file was corrupt, resetting\n")
        return []


def emit_event(event_type: str, detail: str = "", source: str = "collector", snapshot: str = ""):
    """Atomically append one event. Safe to call from multiple processes."""
    _ensure_file()
    with open(EVENTS_FILE, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            events = _load_locked(f)
            events.append({
                "timestamp": time.time(),
                "type": event_type,
                "detail": detail,
                "source": source,
                "snapshot": snapshot,
            })
            events = events[-MAX_EVENTS:]
            f.seek(0)
            f.truncate()
            json.dump(events, f)
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def read_events(limit: int = 20):
    """Return the most recent `limit` events, oldest first."""
    _ensure_file()
    try:
        with open(EVENTS_FILE, "r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                events = _load_locked(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return events[-limit:]
    except Exception as e:
        sys.stderr.write(f"[securevis_common] read_events failed: {e}\n")
        return []


def verdict_for(events) -> str:
    """Shared verdict logic — used by both the live GUI and the forensic report,
    so they can no longer disagree with each other."""
    types = {ev.get("type", "") for ev in events}
    if types & HIGH_SEVERITY:
        return "MALICIOUS"
    if events:
        return "SUSPICIOUS"
    return "CLEAN"


if __name__ == "__main__":
    # CLI mode so the Bash sandbox script can call this instead of
    # hand-rolling its own (unlocked, race-prone) JSON read-modify-write.
    if len(sys.argv) < 2:
        sys.stderr.write("usage: securevis_common.py emit <type> [detail] [source] [snapshot]\n"
                          "       securevis_common.py read [limit]\n")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "emit":
        ev_type = sys.argv[2] if len(sys.argv) > 2 else "UNKNOWN"
        detail = sys.argv[3] if len(sys.argv) > 3 else ""
        source = sys.argv[4] if len(sys.argv) > 4 else "sandbox"
        snapshot = sys.argv[5] if len(sys.argv) > 5 else ""
        emit_event(ev_type, detail, source, snapshot)
    elif cmd == "read":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        for ev in read_events(limit):
            print(json.dumps(ev))
    else:
        sys.stderr.write(f"unknown command: {cmd}\n")
        sys.exit(1)