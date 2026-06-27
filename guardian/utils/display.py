"""Rich-based display utilities for Guardian CLI."""

from __future__ import annotations

import time
from typing import Sequence

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from guardian.engine.alert import Alert, Severity

console = Console()


def render_alert_table(alerts: Sequence[Alert], title: str = "Guardian Alerts") -> Table:
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        expand=True,
    )
    table.add_column("ID", style="dim", width=8)
    table.add_column("Time", style="dim", width=12)
    table.add_column("Module", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=20)
    table.add_column("Description", ratio=2)
    table.add_column("Recommendation", ratio=1)

    for alert in sorted(alerts, key=lambda a: (
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(a.severity.value), a.timestamp
    )):
        t = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        sev_text = Text(alert.severity.value, style=alert.severity.color)
        table.add_row(
            alert.id,
            t,
            alert.module,
            sev_text,
            alert.title,
            alert.description[:120],
            alert.recommendation[:80],
        )
    return table


def print_alert(alert: Alert) -> None:
    color = alert.severity.color
    header = f"[{color}][{alert.severity.value}][/{color}] [{alert.module}] {alert.title}"
    body = (
        f"[bold]Description:[/bold] {alert.description}\n"
        f"[bold]Evidence:[/bold] {alert.evidence}\n"
        f"[bold]Recommendation:[/bold] {alert.recommendation}"
    )
    console.print(Panel(body, title=header, border_style=color, expand=False))


def print_banner() -> None:
    banner = """
[bold red]  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
 ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
 ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
 ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold red]
[dim]  SLM-Powered Cybersecurity Defense System  |  Powered by Phi-3-mini[/dim]
"""
    console.print(banner)
