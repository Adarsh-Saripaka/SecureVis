#!/usr/bin/env python3
"""
securevis-gui.py — terminal dashboard.

Fix vs. the original version: adds a live "Recent Events" panel fed by
the shared event bus (securevis_common), so honeypot trips, RWX
detections, and sandbox anomalies from securevis-sandbox.sh show up
here in real time instead of only appearing in the forensic report
after the sandbox session has already ended.
"""
import json
from datetime import datetime

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable
from textual.containers import Vertical

from securevis_common import read_events, MITRE_MAP, verdict_for

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
    #event_panel {
        padding: 1 2;
        border: round #3a3a3a;
        height: auto;
        max-height: 10;
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

            self.event_panel = Static("No events yet.", id="event_panel")
            yield self.event_panel

            self.table = DataTable(id="process_table")
            yield self.table
        yield Footer()

    def on_mount(self):
        self.set_interval(1, self.update_dashboard)

    def update_dashboard(self):
        self._update_system_and_processes()
        self._update_events()

    def _update_system_and_processes(self):
        try:
            with open(DATA_FILE) as f:
                data = json.load(f)
        except Exception:
            # File may not exist yet if the collector hasn't written its
            # first sample, or may be mid-write. Skip this tick rather
            # than crash the whole dashboard.
            return

        system = data.get("system", {})
        threats = data.get("threats", {})
        processes = data.get("processes", [])

        cpu = system.get("cpu_percent", 0)
        mem = system.get("memory", {}).get("percent", 0)
        disk = system.get("disk", {}).get("percent", 0)
        self.system_panel.update(f"CPU: {cpu:.1f}% | Memory: {mem:.1f}% | Disk: {disk:.1f}%")

        high = threats.get("high", 0)
        medium = threats.get("medium", 0)
        low = threats.get("low", 0)
        self.threat_panel.update(
            f"[red]HIGH: {high}[/red]  [yellow]MEDIUM: {medium}[/yellow]  [green]LOW: {low}[/green]"
        )

        self.table.clear(columns=True)
        self.table.add_columns("PID", "Name", "CPU%", "Avg CPU", "Mem%", "Risk")
        for p in processes:
            risk_display = {
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]",
            }.get(p["risk"], p["risk"])
            self.table.add_row(
                str(p["pid"]), p["name"],
                f"{p['cpu']:.1f}", f"{p['avg_cpu']:.1f}", f"{p['mem']:.1f}",
                risk_display,
            )

    def _update_events(self):
        events = read_events(limit=8)
        if not events:
            self.event_panel.update("No events yet.")
            return

        verdict = verdict_for(read_events(limit=50))
        verdict_color = {"CLEAN": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(verdict, "white")

        lines = [f"[bold]Recent Events[/bold]  (session verdict: [{verdict_color}]{verdict}[/{verdict_color}])"]
        for ev in reversed(events):
            ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%H:%M:%S")
            ev_type = ev.get("type", "UNKNOWN")
            mitre_id, mitre_name = MITRE_MAP.get(ev_type, ("--", "Unclassified"))
            source = ev.get("source", "?")
            detail = ev.get("detail", "")
            color = "red" if ev_type in ("HONEYPOT_ACCESS", "RWX_MEMORY_REGION", "AUTH_FAILURE") else "yellow"
            lines.append(
                f"[{color}]{ts} [{source}] {ev_type}[/{color}] ({mitre_id} {mitre_name}) {detail}"
            )
        self.event_panel.update("\n".join(lines))


if __name__ == "__main__":
    SecureVisDashboard().run()