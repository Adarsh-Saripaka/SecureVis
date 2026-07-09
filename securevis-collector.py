#!/usr/bin/env python3
"""
securevis-collector.py — system-wide monitoring loop.

Fix vs. the original version: it now emits into the shared event bus
(securevis_common) whenever a process *transitions into* HIGH risk,
instead of the dashboard being a completely separate system from the
sandbox's event log. It only fires on the transition (LOW/MEDIUM -> HIGH),
not every second the process stays HIGH, so you get one event per
incident instead of a flood.
"""
import psutil
import json
import time
import os
import sys

from securevis_common import emit_event

DATA_FILE = "/tmp/securevis_data.json"

# Rolling CPU history per PID, for behavior profiling.
PROCESS_HISTORY = {}
# Last known risk level per PID, so we only emit on transition into HIGH.
LAST_RISK = {}

HISTORY_LEN = 15


def collect_system():
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "network": psutil.net_io_counters()._asdict(),
    }


def collect_processes():
    processes = []
    seen_pids = set()

    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            pid = info["pid"]
            seen_pids.add(pid)

            history = PROCESS_HISTORY.setdefault(pid, [])
            history.append(info["cpu_percent"] or 0.0)
            if len(history) > HISTORY_LEN:
                history.pop(0)
            avg_cpu = sum(history) / len(history) if history else 0.0

            anomaly = (info["cpu_percent"] or 0.0) > avg_cpu * 2 if avg_cpu > 0 else False

            score = 0
            if anomaly:
                score += 2
            if (info["cpu_percent"] or 0.0) > 50:
                score += 2
            if (info["memory_percent"] or 0.0) > 20:
                score += 1

            if score >= 4:
                risk = "HIGH"
            elif score >= 2:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # Emit an event only when a process newly enters HIGH risk.
            prev = LAST_RISK.get(pid)
            if risk == "HIGH" and prev != "HIGH":
                emit_event(
                    "HIGH_CPU_ANOMALY",
                    detail=f"pid={pid},name={info['name']},cpu={info['cpu_percent']:.1f}%,avg={avg_cpu:.1f}%",
                    source="collector",
                )
            LAST_RISK[pid] = risk

            processes.append({
                "pid": pid,
                "name": info["name"],
                "cpu": info["cpu_percent"] or 0.0,
                "mem": info["memory_percent"] or 0.0,
                "avg_cpu": round(avg_cpu, 2),
                "anomaly": anomaly,
                "risk": risk,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Prune history/risk state for processes that have exited, so
    # PROCESS_HISTORY/LAST_RISK don't grow forever on a long-running host.
    stale_pids = set(PROCESS_HISTORY) - seen_pids
    for pid in stale_pids:
        PROCESS_HISTORY.pop(pid, None)
        LAST_RISK.pop(pid, None)

    processes = sorted(processes, key=lambda p: p["cpu"], reverse=True)[:10]
    return processes


def threat_summary(processes):
    return {
        "high": len([p for p in processes if p["risk"] == "HIGH"]),
        "medium": len([p for p in processes if p["risk"] == "MEDIUM"]),
        "low": len([p for p in processes if p["risk"] == "LOW"]),
    }


def collect_data():
    system = collect_system()
    processes = collect_processes()
    return {
        "timestamp": time.time(),
        "system": system,
        "processes": processes,
        "threats": threat_summary(processes),
    }


def main():
    print("[SecureVis] Collector started...")
    os.makedirs("/tmp", exist_ok=True)
    while True:
        try:
            data = collect_data()
            tmp_path = DATA_FILE + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f)
            os.replace(tmp_path, DATA_FILE)  # atomic, unlike the old direct write
        except Exception as e:
            # Don't silently die — the original swallowed all errors and
            # kept looping with a stale/partial state file. Surface it.
            print(f"[Collector Error] {e}", file=sys.stderr)
        time.sleep(1)


if __name__ == "__main__":
    main()