#!/usr/bin/env python3
import psutil
import json
import time
import os

DATA_FILE = "/tmp/securevis_data.json"

# Store CPU history for behavior profiling
PROCESS_HISTORY = {}


# -----------------------------
# System Metrics
# -----------------------------
def collect_system():
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "network": psutil.net_io_counters()._asdict()
    }


# -----------------------------
# Process Collection + Profiling
# -----------------------------
def collect_processes():
    processes = []

    for proc in psutil.process_iter(attrs=[
        "pid", "name", "cpu_percent", "memory_percent"
    ]):
        try:
            info = proc.info
            pid = info["pid"]

            # Initialize CPU tracking
            history = PROCESS_HISTORY.setdefault(pid, [])
            history.append(info["cpu_percent"])

            if len(history) > 15:
                history.pop(0)

            avg_cpu = sum(history) / len(history) if history else 0

            # Anomaly detection
            anomaly = (
                info["cpu_percent"] > avg_cpu * 2
                if avg_cpu > 0 else False
            )

            # Risk scoring
            score = 0
            if anomaly:
                score += 2
            if info["cpu_percent"] > 50:
                score += 2
            if info["memory_percent"] > 20:
                score += 1

            if score >= 4:
                risk = "HIGH"
            elif score >= 2:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            processes.append({
                "pid": pid,
                "name": info["name"],
                "cpu": info["cpu_percent"],
                "mem": info["memory_percent"],
                "avg_cpu": round(avg_cpu, 2),
                "anomaly": anomaly,
                "risk": risk
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Top 10 CPU processes
    processes = sorted(
        processes,
        key=lambda p: p["cpu"],
        reverse=True
    )[:10]

    return processes


# -----------------------------
# Threat Summary
# -----------------------------
def threat_summary(processes):
    return {
        "high": len([p for p in processes if p["risk"] == "HIGH"]),
        "medium": len([p for p in processes if p["risk"] == "MEDIUM"]),
        "low": len([p for p in processes if p["risk"] == "LOW"])
    }


# -----------------------------
# Main Data Collection
# -----------------------------
def collect_data():
    system = collect_system()
    processes = collect_processes()

    return {
        "timestamp": time.time(),
        "system": system,
        "processes": processes,
        "threats": threat_summary(processes)
    }


def main():
    print("[SecureVis] Collector started...")

    while True:
        try:
            data = collect_data()

            with open(DATA_FILE, "w") as f:
                json.dump(data, f)

            time.sleep(1)

        except Exception as e:
            print("[Collector Error]", e)
            time.sleep(2)


if __name__ == "__main__":
    os.makedirs("/tmp", exist_ok=True)
    main()
