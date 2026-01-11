#!/usr/bin/env python3
import psutil
import json
import time
import os

DATA_FILE = "/tmp/securevis_data.json"

def collect_data():
    """Collects real-time system stats."""
    data = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "network": psutil.net_io_counters()._asdict(),
        "process_count": len(psutil.pids())
    }
    return data

def main():
    print("[SecureVis] System data collector started...")
    while True:
        try:
            data = collect_data()
            with open(DATA_FILE, "w") as f:
                json.dump(data, f)
            time.sleep(1)
        except Exception as e:
            print("[Error]", e)
            time.sleep(2)

if __name__ == "__main__":
    os.makedirs("/tmp", exist_ok=True)
    main()
