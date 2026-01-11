#!/usr/bin/env python3
import json
import psutil
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable

DATA_FILE = "/tmp/securevis_data.json"

def collect_processes():
    """Collect top CPU processes and write to JSON file."""
    processes = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": info["name"],
                "cpu": info["cpu_percent"],
                "mem": info["memory_percent"]
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by CPU usage and take top 10
    processes = sorted(processes, key=lambda p: p["cpu"], reverse=True)[:10]

    # Write to JSON
    with open(DATA_FILE, "w") as f:
        json.dump({"processes": processes}, f, indent=2)

class Dashboard(App):
    CSS_PATH = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("SecureVis Visualizer", id="title")
        self.table = DataTable(id="process_table")
        yield self.table
        yield Footer()

    def on_mount(self):
        # Collect processes and refresh dashboard every 2 seconds
        self.set_interval(2, self.update_dashboard)

    def update_dashboard(self):
        collect_processes()  # live process collection

        try:
            with open(DATA_FILE) as f:
                data = json.load(f)
        except Exception:
            data = {"processes": []}

        processes = data.get("processes", [])

        self.table.clear(columns=True)
        self.table.add_columns("PID", "Name", "CPU%", "MEM%")

        for proc in processes:
            self.table.add_row(
                str(proc.get("pid", "")),
                proc.get("name", ""),
                f"{proc.get('cpu', 0):.1f}",
                f"{proc.get('mem', 0):.1f}"
            )

if __name__ == "__main__":
    Dashboard().run()
