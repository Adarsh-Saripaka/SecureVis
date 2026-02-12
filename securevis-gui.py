#!/usr/bin/env python3
import json
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable
from textual.containers import Vertical

DATA_FILE = "/tmp/securevis_data.json"


class SecureVisDashboard(App):

    CSS = """
    #system_panel {
        padding: 1 2;
        background: #1e1e1e;
        border: round #3a3a3a;
    }

    #threat_panel {
        padding: 1 2;
        border: round #3a3a3a;
    }

    #process_table {
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Vertical():
            self.system_panel = Static("Loading system data...", id="system_panel")
            yield self.system_panel

            self.threat_panel = Static("Loading threat data...", id="threat_panel")
            yield self.threat_panel

            self.table = DataTable(id="process_table")
            yield self.table

        yield Footer()

    def on_mount(self):
        self.set_interval(1, self.update_dashboard)

    def update_dashboard(self):
        try:
            with open(DATA_FILE) as f:
                data = json.load(f)
        except Exception:
            return

        system = data.get("system", {})
        threats = data.get("threats", {})
        processes = data.get("processes", [])

        # -----------------------
        # System Overview
        # -----------------------
        cpu = system.get("cpu_percent", 0)
        mem = system.get("memory", {}).get("percent", 0)
        disk = system.get("disk", {}).get("percent", 0)

        self.system_panel.update(
            f"CPU: {cpu:.1f}%   |   "
            f"Memory: {mem:.1f}%   |   "
            f"Disk: {disk:.1f}%"
        )

        # -----------------------
        # Threat Summary
        # -----------------------
        high = threats.get("high", 0)
        medium = threats.get("medium", 0)
        low = threats.get("low", 0)

        self.threat_panel.update(
            f"[red]HIGH: {high}[/red]   "
            f"[yellow]MEDIUM: {medium}[/yellow]   "
            f"[green]LOW: {low}[/green]"
        )

        # -----------------------
        # Process Table
        # -----------------------
        self.table.clear(columns=True)
        self.table.add_columns(
            "PID", "Name", "CPU%", "Avg CPU", "Mem%", "Risk"
        )

        for p in processes:

            if p["risk"] == "HIGH":
                risk_display = "[red]HIGH[/red]"
            elif p["risk"] == "MEDIUM":
                risk_display = "[yellow]MEDIUM[/yellow]"
            else:
                risk_display = "[green]LOW[/green]"

            self.table.add_row(
                str(p["pid"]),
                p["name"],
                f"{p['cpu']:.1f}",
                f"{p['avg_cpu']:.1f}",
                f"{p['mem']:.1f}",
                risk_display
            )


if __name__ == "__main__":
    SecureVisDashboard().run()
