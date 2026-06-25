"""Guardian CLI — main entrypoint."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich import box

from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import get_correlator, Campaign, CampaignStatus
from guardian.engine.responder import AutoResponder, ResponseResult
from guardian.utils.display import console, print_alert, print_banner, render_alert_table
from guardian.utils.report import save_json_report

_alert_store: list[Alert] = []
_store_lock = threading.Lock()
_responder: AutoResponder | None = None
_enricher = None      # set to AlertEnricher instance when TI feeds are loaded
_web_state = None     # set to DashboardState when serve is active


def _on_response(result: ResponseResult) -> None:
    color = "green" if result.success else "red"
    dry = " [DRY RUN]" if result.dry_run else ""
    console.print(f"  [{color}][RESPONSE{dry}][/{color}] {result.message}")


def _on_campaign(campaign: Campaign) -> None:
    tactics = " → ".join(campaign.tactics) or "Unknown"
    title = campaign.title or f"Campaign {campaign.id}"
    body = (
        f"[bold]Tactics:[/bold] {tactics}\n"
        f"[bold]Alerts:[/bold] {len(campaign.alerts)} across "
        f"{len({a.module for a in campaign.alerts})} modules\n"
        f"[bold]Duration:[/bold] {campaign.duration_secs:.0f}s\n"
    )
    if campaign.synthesis:
        body += f"[bold]Narrative:[/bold] {campaign.synthesis}"
    console.print(Panel(
        body,
        title=f"[bold red][CAMPAIGN][/bold red] {title}",
        border_style="bold red",
        expand=False,
    ))
    if _responder:
        _responder.respond_to_campaign(campaign)

    # Push campaign to web dashboard
    if _web_state is not None:
        _web_state.ingest_campaign(campaign)


def _store_alert(alert: Alert) -> None:
    global _enricher
    with _store_lock:
        _alert_store.append(alert)

    # Enrich with TI before display so IOC tags show in the alert panel
    # (skip for global_feed — those alerts already carry source IOC metadata)
    if _enricher is not None and alert.module != "global_feed":
        matches = _enricher(alert)
        if matches:
            tag = alert.metadata.get("ioc_tag", "")
            families = sorted({m.malware_family for m in matches if m.malware_family})
            family_str = f" | Malware: {', '.join(families)}" if families else ""
            console.print(
                f"  [bold red][TI MATCH][/bold red] {tag}{family_str}"
            )

    print_alert(alert)

    # Push to web dashboard
    if _web_state is not None:
        _web_state.ingest_alert(alert)

    # Feed every alert through the correlator
    correlator = get_correlator(on_campaign=_on_campaign)
    correlator.ingest(alert)
    if _responder:
        _responder.respond_to_alert(alert)


def _init_ti(no_ti: bool = False, force_refresh: bool = False) -> None:
    """Load TI feeds into the global enricher (non-fatal if feeds unavailable)."""
    global _enricher
    if no_ti:
        return
    try:
        from guardian.intel.feeds import get_index, start_background_refresh
        from guardian.intel.enricher import AlertEnricher

        with console.status("[dim]Loading threat intelligence feeds...[/dim]"):
            index = get_index(force_refresh=force_refresh)

        loaded = len(index.loaded_feeds)
        errors = len(index.errors)
        console.print(
            f"  [green]✓[/green] Threat intel: "
            f"{index.total_iocs:,} IOCs from {loaded} feeds"
            + (f" [yellow]({errors} failed)[/yellow]" if errors else "")
        )
        _enricher = AlertEnricher(index)
        start_background_refresh()
    except Exception as e:
        console.print(f"  [yellow]TI feeds unavailable: {e}[/yellow]")


@click.group()
@click.version_option(package_name="guardian-sec")
def cli() -> None:
    """Guardian — SLM-powered local cybersecurity defense system."""
    pass


# ─── download-model ──────────────────────────────────────────────────────────

@cli.command("download-model")
@click.option("--model-dir", default=None, help="Directory to save the model (default: ./models/)")
@click.option("--quantization", default="Q4_K_M", show_default=True,
              type=click.Choice(["Q2_K", "Q4_K_M", "Q5_K_M", "Q8_0"]),
              help="GGUF quantization level")
def download_model(model_dir: Optional[str], quantization: str) -> None:
    """Download Phi-3-mini GGUF model from Hugging Face."""
    import urllib.request

    model_dir_path = Path(model_dir) if model_dir else Path(__file__).parents[1] / "models"
    model_dir_path.mkdir(parents=True, exist_ok=True)

    quant_map = {
        "Q2_K": "Phi-3-mini-4k-instruct-q2_k.gguf",
        "Q4_K_M": "Phi-3-mini-4k-instruct-q4.gguf",
        "Q5_K_M": "Phi-3-mini-4k-instruct-q5_k_m.gguf",
        "Q8_0": "Phi-3-mini-4k-instruct-q8_0.gguf",
    }
    filename = quant_map[quantization]
    dest = model_dir_path / filename

    if dest.exists():
        console.print(f"[green]Model already exists at {dest}[/green]")
        return

    url = (
        f"https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/{filename}"
    )
    console.print(f"[bold]Downloading {filename}...[/bold]")
    console.print(f"[dim]URL: {url}[/dim]")
    console.print("[dim]This may take a few minutes depending on your connection.[/dim]")

    def _progress(block_num: int, block_size: int, total_size: int) -> None:
        downloaded = block_num * block_size
        if total_size > 0:
            pct = min(100, downloaded * 100 // total_size)
            mb = downloaded / 1_048_576
            total_mb = total_size / 1_048_576
            print(f"\r  {pct:3d}%  {mb:.1f}/{total_mb:.1f} MB", end="", flush=True)

    try:
        urllib.request.urlretrieve(url, str(dest), _progress)
        print()
        console.print(f"[green]Model saved to {dest}[/green]")
        console.print("[dim]Run: guardian scan-code <path>  or  guardian watch-logs[/dim]")
    except Exception as e:
        console.print(f"[red]Download failed: {e}[/red]")
        sys.exit(1)


# ─── scan-code ───────────────────────────────────────────────────────────────

@cli.command("scan-code")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save JSON report to this file")
@click.option("--exclude", "-x", multiple=True, help="Directory names to exclude (repeatable)")
@click.option("--model", default=None, help="Override model path")
def scan_code(path: str, output: Optional[str], exclude: tuple, model: Optional[str]) -> None:
    """Scan source code or a directory for vulnerabilities."""
    print_banner()
    _load_engine(model)

    from guardian.modules.code_scanner import scan_directory, scan_file

    target = Path(path)
    alerts: list[Alert] = []

    with console.status(f"[bold green]Scanning {target}...[/bold green]"):
        try:
            if target.is_file():
                for a in scan_file(target):
                    alerts.append(a)
                    print_alert(a)
            else:
                for a in scan_directory(target, exclude=list(exclude)):
                    alerts.append(a)
                    print_alert(a)
        except FileNotFoundError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

    if not alerts:
        console.print("[green]No vulnerabilities found.[/green]")
    else:
        console.print(render_alert_table(alerts, title="Code Scan Results"))

    if output:
        save_json_report(alerts, output)
        console.print(f"[dim]Report saved to {output}[/dim]")


# ─── scan-config ─────────────────────────────────────────────────────────────

@cli.command("scan-config")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save JSON report to this file")
@click.option("--model", default=None, help="Override model path")
def scan_config(path: str, output: Optional[str], model: Optional[str]) -> None:
    """Audit a configuration or .env file for security issues."""
    print_banner()
    _load_engine(model)

    from guardian.modules.code_scanner import scan_config as _scan_config

    alerts: list[Alert] = []
    with console.status("[bold green]Auditing config...[/bold green]"):
        for a in _scan_config(path):
            alerts.append(a)
            print_alert(a)

    if not alerts:
        console.print("[green]No issues found.[/green]")
    else:
        console.print(render_alert_table(alerts, title="Config Audit"))

    if output:
        save_json_report(alerts, output)
        console.print(f"[dim]Report saved to {output}[/dim]")


# ─── watch-logs ──────────────────────────────────────────────────────────────

@cli.command("watch-logs")
@click.argument("files", nargs=-1, required=False)
@click.option("--model", default=None, help="Override model path")
@click.option("--output", "-o", default=None, help="Save JSON report on exit")
def watch_logs(files: tuple, model: Optional[str], output: Optional[str]) -> None:
    """Tail log files and detect threats in real time."""
    print_banner()
    _load_engine(model)

    default_logs = [
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/secure", "/var/log/messages",
    ]
    log_files = list(files) or [f for f in default_logs if Path(f).exists()]

    if not log_files:
        console.print("[yellow]No log files found. Pass file paths as arguments.[/yellow]")
        sys.exit(1)

    from guardian.modules.log_analyzer import LogAnalyzer

    console.print(f"[bold]Watching:[/bold] {', '.join(log_files)}")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    analyzer = LogAnalyzer(log_files, _store_alert)
    analyzer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        analyzer.stop()
        console.print("\n[dim]Stopped.[/dim]")

    if output and _alert_store:
        save_json_report(_alert_store, output)
        console.print(f"[dim]Report saved to {output}[/dim]")


# ─── scan-logs ───────────────────────────────────────────────────────────────

@cli.command("scan-logs")
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save JSON report")
@click.option("--model", default=None, help="Override model path")
def scan_logs(file: str, output: Optional[str], model: Optional[str]) -> None:
    """One-shot scan of a log file."""
    print_banner()
    _load_engine(model)

    from guardian.modules.log_analyzer import scan_file

    alerts: list[Alert] = []
    with console.status("[bold green]Analyzing log file...[/bold green]"):
        for a in scan_file(file):
            alerts.append(a)
            print_alert(a)

    if not alerts:
        console.print("[green]No threats detected in log file.[/green]")
    else:
        console.print(render_alert_table(alerts, title="Log Scan Results"))

    if output:
        save_json_report(alerts, output)


# ─── watch-network ───────────────────────────────────────────────────────────

@cli.command("watch-network")
@click.option("--iface", "-i", default=None, help="Network interface to sniff (default: auto)")
@click.option("--output", "-o", default=None, help="Save JSON report on exit")
@click.option("--model", default=None, help="Override model path")
def watch_network(iface: Optional[str], output: Optional[str], model: Optional[str]) -> None:
    """Monitor live network traffic for threats (requires root/admin)."""
    print_banner()
    _load_engine(model)

    from guardian.modules.network_monitor import NetworkMonitor

    console.print("[bold]Starting network monitor...[/bold]")
    if iface:
        console.print(f"[dim]Interface: {iface}[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    monitor = NetworkMonitor(_store_alert, iface=iface)
    monitor.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        monitor.stop()
        console.print("\n[dim]Stopped.[/dim]")

    if output and _alert_store:
        save_json_report(_alert_store, output)
        console.print(f"[dim]Report saved to {output}[/dim]")


# ─── scan-pcap ───────────────────────────────────────────────────────────────

@cli.command("scan-pcap")
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save JSON report")
@click.option("--model", default=None, help="Override model path")
def scan_pcap(file: str, output: Optional[str], model: Optional[str]) -> None:
    """Analyze a PCAP file for network threats."""
    print_banner()
    _load_engine(model)

    from guardian.modules.network_monitor import analyze_pcap

    with console.status("[bold green]Analyzing PCAP...[/bold green]"):
        alerts = analyze_pcap(file)

    for a in alerts:
        print_alert(a)

    if not alerts:
        console.print("[green]No threats detected in PCAP.[/green]")
    else:
        console.print(render_alert_table(alerts, title="PCAP Analysis"))

    if output:
        save_json_report(alerts, output)


# ─── watch-files ─────────────────────────────────────────────────────────────

@cli.command("watch-files")
@click.argument("paths", nargs=-1, required=False)
@click.option("--output", "-o", default=None, help="Save JSON report on exit")
@click.option("--model", default=None, help="Override model path")
def watch_files(paths: tuple, output: Optional[str], model: Optional[str]) -> None:
    """Monitor filesystem changes for malware and tampering."""
    print_banner()
    _load_engine(model)

    from guardian.modules.file_monitor import FileIntegrityMonitor, ProcessMonitor

    watch_paths = list(paths) or ["/etc", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"]
    existing = [p for p in watch_paths if Path(p).exists()]

    if not existing:
        console.print("[yellow]No valid paths to watch.[/yellow]")
        sys.exit(1)

    console.print(f"[bold]Watching:[/bold] {', '.join(existing)}")
    console.print("[dim]Building baseline...[/dim]")

    fim = FileIntegrityMonitor(existing, _store_alert)
    pm = ProcessMonitor(_store_alert)

    fim.start()
    pm.start()

    console.print("[green]Baseline built. Monitoring active.[/green]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        fim.stop()
        pm.stop()
        console.print("\n[dim]Stopped.[/dim]")

    if output and _alert_store:
        save_json_report(_alert_store, output)
        console.print(f"[dim]Report saved to {output}[/dim]")


# ─── scan-processes ──────────────────────────────────────────────────────────

@cli.command("scan-processes")
@click.option("--output", "-o", default=None, help="Save JSON report")
@click.option("--model", default=None, help="Override model path")
def scan_processes(output: Optional[str], model: Optional[str]) -> None:
    """One-shot scan of all running processes for suspicious activity."""
    print_banner()
    _load_engine(model)

    from guardian.modules.file_monitor import scan_processes_once

    with console.status("[bold green]Scanning running processes...[/bold green]"):
        alerts = scan_processes_once()

    for a in alerts:
        print_alert(a)

    if not alerts:
        console.print("[green]No suspicious processes found.[/green]")
    else:
        console.print(render_alert_table(alerts, title="Process Scan"))

    if output:
        save_json_report(alerts, output)


# ─── defend (all-in-one daemon) ──────────────────────────────────────────────

@cli.command("defend")
@click.option("--log-files", "-l", multiple=True, help="Log files to watch")
@click.option("--watch-dirs", "-w", multiple=True, help="Directories to watch")
@click.option("--iface", "-i", default=None, help="Network interface (requires root)")
@click.option("--output", "-o", default=None, help="Save JSON report on exit")
@click.option("--model", default=None, help="Override model path")
@click.option("--respond", is_flag=True, default=False,
              help="Enable active response (kill processes, block IPs, quarantine files)")
@click.option("--respond-live", is_flag=True, default=False,
              help="Active response without dry-run (CAUTION: takes real action)")
@click.option("--no-ti", is_flag=True, default=False, help="Disable threat intelligence feeds")
@click.option("--refresh-feeds", is_flag=True, default=False, help="Force-refresh TI feed cache")
def defend(
    log_files: tuple,
    watch_dirs: tuple,
    iface: Optional[str],
    output: Optional[str],
    model: Optional[str],
    respond: bool,
    respond_live: bool,
    no_ti: bool,
    refresh_feeds: bool,
) -> None:
    """Run ALL Guardian modules simultaneously — full defensive coverage."""
    global _responder
    print_banner()
    _load_engine(model)
    _init_ti(no_ti=no_ti, force_refresh=refresh_feeds)

    from guardian.modules.log_analyzer import LogAnalyzer
    from guardian.modules.network_monitor import NetworkMonitor
    from guardian.modules.file_monitor import FileIntegrityMonitor, ProcessMonitor
    from guardian.engine.responder import AutoResponder

    # Start correlator
    correlator = get_correlator(on_campaign=_on_campaign)

    # Set up responder
    if respond_live:
        console.print("[bold red]Active response LIVE mode enabled — will take real action.[/bold red]")
        _responder = AutoResponder(dry_run=False, on_response=_on_response)
    elif respond:
        console.print("[yellow]Active response DRY RUN mode — will log but not execute.[/yellow]")
        _responder = AutoResponder(dry_run=True, on_response=_on_response)

    default_logs = [
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/secure", "/var/log/messages",
    ]
    logs = list(log_files) or [f for f in default_logs if Path(f).exists()]
    dirs = list(watch_dirs) or ["/etc", "/tmp", "/var/tmp"]
    existing_dirs = [d for d in dirs if Path(d).exists()]

    modules_started: list[str] = []

    if logs:
        la = LogAnalyzer(logs, _store_alert)
        la.start()
        modules_started.append(f"Log monitor ({len(logs)} files)")

    if existing_dirs:
        fim = FileIntegrityMonitor(existing_dirs, _store_alert)
        pm = ProcessMonitor(_store_alert)
        fim.start()
        pm.start()
        modules_started.append(f"File/process monitor ({len(existing_dirs)} dirs)")

    net = NetworkMonitor(_store_alert, iface=iface)
    net.start()
    modules_started.append("Network monitor")
    modules_started.append("Threat correlator")

    if global_ticker:
        from guardian.intel.global_ticker import start_global_ticker
        start_global_ticker(_store_alert, interval_secs=global_interval)
        modules_started.append(f"Global threat ticker ({global_interval}s poll)")

    console.print("[bold green]Guardian is active.[/bold green]")
    for m in modules_started:
        console.print(f"  [green]✓[/green] {m}")
    if _responder:
        mode = "LIVE" if respond_live else "dry-run"
        console.print(f"  [green]✓[/green] Active responder ({mode})")
    console.print("[dim]Press Ctrl+C to stop.\n[/dim]")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Shutting down...[/dim]")

    # Print campaign summary on exit
    campaigns = correlator.get_campaigns(active_only=False)
    if campaigns:
        console.print(f"\n[bold]Campaigns detected this session: {len(campaigns)}[/bold]")
        for c in campaigns[:5]:
            tactics = " → ".join(c.tactics) or "Unknown"
            console.print(
                f"  [red]{c.id}[/red] {c.title or 'Unnamed'} | "
                f"{len(c.alerts)} alerts | {tactics}"
            )

    if output and _alert_store:
        import json
        report = {
            "alerts": [a.to_dict() for a in _alert_store],
            "campaigns": [c.to_dict() for c in campaigns],
        }
        Path(output).write_text(json.dumps(report, indent=2))
        console.print(f"[dim]Session report saved to {output}[/dim]")
        console.print(f"[dim]Alerts: {len(_alert_store)} | Campaigns: {len(campaigns)}[/dim]")


# ─── campaigns ───────────────────────────────────────────────────────────────

@cli.command("campaigns")
def campaigns_cmd() -> None:
    """Show active attack campaigns detected this session."""
    correlator = get_correlator()
    active = correlator.get_campaigns(active_only=True)

    if not active:
        console.print("[dim]No active campaigns.[/dim]")
        return

    table = Table(title="Active Campaigns", box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("ID", style="dim", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=20)
    table.add_column("Alerts", width=7)
    table.add_column("Tactics (kill chain)", ratio=2)
    table.add_column("Duration", width=10)
    table.add_column("Status", width=12)

    for c in active:
        tactics = " → ".join(c.tactics) or "Unknown"
        duration = f"{c.duration_secs:.0f}s"
        sev_text = Text(c.severity.value, style=c.severity.color)
        status_color = "green" if c.status == CampaignStatus.SYNTHESIZED else "yellow"
        table.add_row(
            c.id,
            sev_text,
            c.title or f"Campaign {c.id[:6]}",
            str(len(c.alerts)),
            tactics,
            duration,
            Text(c.status.value, style=status_color),
        )

    console.print(table)

    for c in active:
        if c.synthesis:
            console.print(Panel(
                c.synthesis,
                title=f"[bold]{c.title or c.id}[/bold] — Attack Narrative",
                border_style="red",
                expand=False,
            ))


# ─── check-ioc ───────────────────────────────────────────────────────────────

@cli.command("check-ioc")
@click.argument("value")
@click.option("--refresh", is_flag=True, default=False, help="Force-refresh feed cache first")
def check_ioc(value: str, refresh: bool) -> None:
    """Check an IP, domain, hash, or URL against threat intelligence feeds."""
    from guardian.intel.feeds import get_index

    with console.status("[dim]Loading TI feeds...[/dim]"):
        try:
            index = get_index(force_refresh=refresh)
        except Exception as e:
            console.print(f"[red]Failed to load feeds: {e}[/red]")
            sys.exit(1)

    from guardian.intel.heuristics import check_value

    matches = index.lookup(value)
    suspicious = check_value(value)

    if not matches and not suspicious:
        console.print(f"[green]CLEAN[/green] — {value} not found in any TI feed or suspicious platform list ({index.total_iocs:,} IOCs checked)")
        return

    if matches:
        console.print(f"[bold red]MALICIOUS[/bold red] — {value} matched {len(matches)} confirmed TI feed(s):\n")
        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Feed", style="red")
        table.add_column("IOC Type")
        table.add_column("Malware Family")
        table.add_column("Confidence")
        for m in matches:
            table.add_row(
                m.feed,
                m.ioc_type,
                m.malware_family or "[dim]—[/dim]",
                f"{m.confidence}%",
            )
        console.print(table)

    if suspicious:
        console.print(f"\n[bold yellow]SUSPICIOUS[/bold yellow] — {value} matches known-abused platform:\n")
        table2 = Table(box=box.ROUNDED, show_lines=True)
        table2.add_column("Category", style="yellow")
        table2.add_column("Confidence")
        table2.add_column("Reason")
        table2.add_column("Example Abuse")
        table2.add_row(
            suspicious.category,
            f"{suspicious.confidence}%",
            suspicious.reason,
            suspicious.example_abuse,
        )
        console.print(table2)


# ─── update-feeds ─────────────────────────────────────────────────────────────

@cli.command("update-feeds")
def update_feeds() -> None:
    """Force-refresh all threat intelligence feed caches."""
    from guardian.intel.feeds import FEEDS, load_feeds, _cache_path

    console.print(f"[bold]Updating {len(FEEDS)} TI feeds...[/bold]\n")
    errors: list[str] = []

    def _progress(msg: str) -> None:
        console.print(f"  [dim]{msg}[/dim]")

    index = load_feeds(force_refresh=True, progress_cb=_progress)

    console.print(f"\n[green]Done.[/green] {index.total_iocs:,} IOCs loaded from {len(index.loaded_feeds)} feeds.")
    if index.errors:
        console.print(f"[yellow]{len(index.errors)} feed(s) failed:[/yellow]")
        for e in index.errors:
            console.print(f"  [dim]{e}[/dim]")


# ─── feed-status ──────────────────────────────────────────────────────────────

@cli.command("feed-status")
def feed_status_cmd() -> None:
    """Show status and freshness of all TI feed caches."""
    from guardian.intel.feeds import feed_status

    rows = feed_status()
    table = Table(title="Threat Intelligence Feed Status", box=box.ROUNDED, show_lines=True)
    table.add_column("Feed", min_width=28)
    table.add_column("Type", width=8)
    table.add_column("Cached", width=8)
    table.add_column("Fresh", width=7)
    table.add_column("Age (min)", width=10)
    table.add_column("Size (KB)", width=10)
    table.add_column("TTL (min)", width=10)

    for r in rows:
        cached_style = "green" if r["cached"] else "red"
        fresh_style = "green" if r["fresh"] else ("yellow" if r["cached"] else "red")
        age = f"{r['age_mins']}" if r["age_mins"] is not None else "[dim]—[/dim]"
        table.add_row(
            r["feed"],
            r["ioc_type"],
            Text("yes" if r["cached"] else "no", style=cached_style),
            Text("yes" if r["fresh"] else "no", style=fresh_style),
            age,
            str(r["size_kb"]),
            str(r["ttl_mins"]),
        )
    console.print(table)



# ─── test-alert ───────────────────────────────────────────────────────────────

@cli.command("test-alert")
@click.option("--host", default="127.0.0.1", show_default=True, help="Dashboard host")
@click.option("--port", default=8765, show_default=True, help="Dashboard port")
@click.option("--title", default="Live feed test", show_default=True, help="Alert title")
@click.option("--severity", default="HIGH", show_default=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
def test_alert_cmd(host: str, port: int, title: str, severity: str) -> None:
    """Send a test alert to a running Guardian dashboard."""
    import json
    import urllib.error
    import urllib.request

    url = f"http://{host}:{port}/api/test-alert"
    payload = json.dumps({"title": title, "severity": severity}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        console.print(f"[red]Could not reach dashboard at {url}[/red]")
        console.print("[dim]Start it first: python3 -m guardian.cli serve[/dim]")
        console.print(f"[dim]{e}[/dim]")
        sys.exit(1)

    console.print(f"[green]Test alert sent:[/green] {data.get('title')} (id={data.get('id')})")


# ─── cross-verify ─────────────────────────────────────────────────────────────

def _print_cross_verify_summary(data: dict) -> None:
    """Render cross-verify JSON (single result or batch summary) to the console."""
    from rich.table import Table

    if "summary" in data:
        s = data["summary"]
        console.print(
            f"[bold]Summary:[/bold] {s['total_alerts']} alerts — "
            f"[green]{s['genuine']} genuine[/green], "
            f"[yellow]{s['unverified']} unverified[/yellow], "
            f"[red]{s['false_positive']} false positive[/red]"
        )
        if s.get("skipped_auth_sources"):
            console.print(
                "[yellow]Skipped (auth/rate limit):[/yellow] "
                + ", ".join(sorted(set(s["skipped_auth_sources"])))
            )
        table = Table(title="Cross-verification results", box=box.ROUNDED, show_lines=True)
        for col in ("alert", "type", "classification", "confidence", "reference"):
            table.add_column(col.replace("_", " ").title(), overflow="fold")
        for row in data.get("rows", []):
            style = {
                "GENUINE": "green",
                "FALSE POSITIVE": "red",
            }.get(row.get("classification", ""), "yellow")
            table.add_row(
                row.get("alert", ""),
                row.get("type", ""),
                Text(row.get("classification", ""), style=style),
                row.get("confidence", ""),
                row.get("reference", "")[:120],
            )
        console.print(table)
        return

    cls = data.get("classification", "UNVERIFIED")
    style = {"GENUINE": "green", "FALSE POSITIVE": "red"}.get(cls, "yellow")
    console.print(Panel(
        f"[bold]Classification:[/bold] [{style}]{cls}[/{style}] ({data.get('confidence', '')})\n"
        f"[bold]Rationale:[/bold] {data.get('rationale', '')}\n"
        f"[bold]Corroboration:[/bold] {data.get('corroboration_count', 0)}",
        title=f"Cross-verify: {data.get('indicator', '')}",
        border_style=style,
    ))
    if data.get("skipped_sources"):
        console.print("[yellow]Skipped:[/yellow] " + "; ".join(data["skipped_sources"]))
    errors = [
        f"{c['source']}: {c['detail']}"
        for c in data.get("checks", [])
        if c.get("status") == "error" and c.get("detail")
    ]
    if errors:
        console.print("[red]Source errors:[/red]")
        for e in errors:
            console.print(f"  {e}")


def _fetch_dashboard_alerts(host: str, port: int, limit: int) -> list[dict]:
    import json
    import urllib.error
    import urllib.request

    url = f"http://{host}:{port}/api/alerts?limit={limit}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        console.print(f"[red]Could not reach dashboard at http://{host}:{port}[/red]")
        console.print("[dim]Start it first: python3 -m guardian.cli serve[/dim]")
        console.print(f"[dim]{e}[/dim]")
        sys.exit(1)


@cli.command("cross-verify")
@click.option("--host", default="127.0.0.1", show_default=True, help="Dashboard host (for --all / --alert-id)")
@click.option("--port", default=8765, show_default=True, help="Dashboard port")
@click.option("--alert-id", default=None, help="Verify one alert by ID (from dashboard or /api/alerts)")
@click.option("--ioc", default=None, help="Verify a raw IOC — no dashboard required")
@click.option("--ioc-type", default=None, help="IOC type: ip, domain, url, hash, cve")
@click.option("--all", "verify_all", is_flag=True, help="Verify alerts from the running dashboard")
@click.option("--limit", default=20, show_default=True, help="Max alerts when using --all")
def cross_verify_cmd(
    host: str,
    port: int,
    alert_id: Optional[str],
    ioc: Optional[str],
    ioc_type: Optional[str],
    verify_all: bool,
    limit: int,
) -> None:
    """Run 5-stage cross-source verification (AbuseIPDB, abuse.ch, NVD, CISA KEV)."""
    from guardian.intel.cross_verify import key_status_message, verify_alert_dict, verify_alerts

    key_msg = key_status_message()
    if key_msg:
        console.print(f"[yellow]{key_msg}[/yellow]")

    if not (verify_all or alert_id or ioc):
        console.print("[yellow]Provide one of:[/yellow]")
        console.print("  --ioc 'http://example.com/bad'     [dim](no dashboard needed)[/dim]")
        console.print("  --all --limit 20                   [dim](needs serve running)[/dim]")
        console.print("  --alert-id abc123-def456           [dim](real ID, not literal <uuid>)[/dim]")
        console.print("[dim]List IDs: curl -s http://127.0.0.1:8765/api/alerts | python3 -m json.tool[/dim]")
        sys.exit(1)

    if ioc:
        synthetic = {
            "id": "manual",
            "evidence": ioc,
            "title": "Manual IOC check",
            "metadata": {"ioc_value": ioc, "ioc_type": ioc_type or "", "global_source": "manual"},
        }
        _print_cross_verify_summary(verify_alert_dict(synthetic).to_dict())
        return

    alerts = _fetch_dashboard_alerts(host, port, limit if verify_all else 500)

    if alert_id:
        match = next((a for a in alerts if a.get("id") == alert_id), None)
        if not match:
            matches = [a for a in alerts if str(a.get("id", "")).startswith(alert_id)]
            if len(matches) == 1:
                match = matches[0]
            elif len(matches) > 1:
                console.print(f"[yellow]Multiple alerts match prefix {alert_id}:[/yellow]")
                for a in matches[:8]:
                    console.print(f"  {a.get('id')}  {a.get('title', '')[:60]}")
                sys.exit(1)
        if not match:
            console.print(f"[red]Alert not found:[/red] {alert_id}")
            console.print(
                "[dim]IDs rotate as new alerts arrive (max ~500 in memory). "
                "Use a recent ID below or --ioc for a raw indicator.[/dim]"
            )
            console.print("[dim]Recent IDs:[/dim]")
            for a in alerts[:8]:
                console.print(f"  {a.get('id')}  {a.get('title', '')[:60]}")
            sys.exit(1)
        _print_cross_verify_summary(verify_alert_dict(match).to_dict())
        return

    batch = alerts[:limit]
    if not batch:
        console.print("[yellow]No alerts on the dashboard yet.[/yellow]")
        sys.exit(0)
    _print_cross_verify_summary(verify_alerts(batch).to_dict())


def _load_env_file() -> None:
    """Load project .env into os.environ (overrides defaults, like bash source)."""
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ[key] = val


def _apply_serve_env_defaults() -> None:
    """Match scripts/open-guardian.sh defaults, then apply .env overrides."""
    os.environ.setdefault("GUARDIAN_INSECURE_SSL", "1")
    os.environ.setdefault("GUARDIAN_BREACH_PROVIDER", "auto")
    _load_env_file()


def _dashboard_url(host: str, port: int) -> str:
    try:
        from guardian.web.server import dashboard_base_url
        return dashboard_base_url(host, port)
    except ImportError:
        return f"http://{host}:{port}/"


def _probe_server(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        from guardian.web.server import wait_for_server_ready
    except ImportError:
        return False
    return wait_for_server_ready(host, port, timeout=timeout)


def _open_browser(url: str) -> None:
    """Open the dashboard in the default browser (Windows browser when run from WSL)."""
    if os.environ.get("WSL_DISTRO_NAME"):
        try:
            subprocess.run(
                ["cmd.exe", "/c", "start", "", url],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except OSError:
            pass
    webbrowser.open(url)


def _spawn_serve_background(host: str, port: int, extra_args: tuple[str, ...] = ()) -> subprocess.Popen:
    _apply_serve_env_defaults()
    env = os.environ.copy()
    project_root = Path(__file__).resolve().parents[1]
    cmd = [
        sys.executable,
        "-m",
        "guardian.cli",
        "serve",
        "--host",
        host,
        "--port",
        str(port),
        *extra_args,
    ]
    return subprocess.Popen(
        cmd,
        cwd=str(project_root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


@cli.command("open")
@click.option("--host", default="127.0.0.1", show_default=True, help="Dashboard host")
@click.option("--port", default=8765, show_default=True, help="Dashboard port")
@click.option("--no-start", is_flag=True, default=False, help="Only open the browser; do not start serve")
@click.option("--no-ti", is_flag=True, default=False, help="When starting serve, disable local TI feeds")
def open_dashboard(host: str, port: int, no_start: bool, no_ti: bool) -> None:
    """One-click launcher — start Guardian if needed, then open the dashboard in your browser."""
    url = _dashboard_url(host, port)

    if _probe_server(host, port):
        console.print(f"[green]Guardian is already running[/green] — opening {url}")
        _open_browser(url)
        return

    if no_start:
        console.print(f"[red]Guardian is not running at {url}[/red]")
        console.print("[dim]Start it with: python3 -m guardian.cli serve[/dim]")
        sys.exit(1)

    console.print(f"[dim]Starting Guardian at {url} ...[/dim]")
    extra = ("--no-ti",) if no_ti else ()
    _spawn_serve_background(host, port, extra)

    if not _probe_server(host, port, timeout=90.0):
        console.print(f"[red]Timed out waiting for Guardian at {url}[/red]")
        console.print("[dim]Run serve in a terminal to see startup errors.[/dim]")
        sys.exit(1)

    console.print(f"[bold green]Guardian is ready[/bold green] — opening {url}")
    _open_browser(url)
    console.print("[dim]Bookmark this URL. Server keeps running in the background.[/dim]")
    console.print("[dim]Stop it with: pkill -f 'guardian.cli serve'[/dim]")


# ─── serve ───────────────────────────────────────────────────────────────────

@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8765, show_default=True, help="Bind port")
@click.option("--log-files", "-l", multiple=True, help="Log files to watch")
@click.option("--watch-dirs", "-w", multiple=True, help="Directories to watch")
@click.option("--iface", "-i", default=None, help="Network interface (requires root)")
@click.option("--model", default=None, help="Override model path")
@click.option("--no-ti", is_flag=True, default=False, help="Disable TI feeds")
@click.option("--refresh-feeds", is_flag=True, default=False, help="Force-refresh TI feed cache")
@click.option("--respond", is_flag=True, default=False, help="Active response dry-run")
@click.option("--respond-live", is_flag=True, default=False, help="Active response live mode")
@click.option("--global-ticker/--no-global-ticker", default=True, show_default=True,
              help="Poll global TI APIs and surface new threats on the dashboard")
@click.option("--global-interval", default=120, show_default=True,
              help="Seconds between global threat feed polls")
@click.option("--open", "open_browser", is_flag=True, default=False,
              help="Open the dashboard in your default browser once ready")
def serve(
    host: str,
    port: int,
    log_files: tuple,
    watch_dirs: tuple,
    iface: Optional[str],
    model: Optional[str],
    no_ti: bool,
    refresh_feeds: bool,
    respond: bool,
    respond_live: bool,
    global_ticker: bool,
    global_interval: int,
    open_browser: bool,
) -> None:
    """Run Guardian + live web dashboard at http://HOST:PORT/"""
    global _responder, _web_state

    _apply_serve_env_defaults()
    print_banner()

    try:
        from guardian.web.server import run_server_background, state, wait_for_server_ready
    except ImportError:
        console.print("[red]FastAPI and uvicorn are required for the web dashboard.[/red]")
        console.print("[yellow]Run: pip install fastapi uvicorn[/yellow]")
        sys.exit(1)

    _load_engine(model)
    _init_ti(no_ti=no_ti, force_refresh=refresh_feeds)

    # Set up dashboard state
    _web_state = state

    # Start web server BEFORE defense modules so the broadcast queue is wired
    # before any monitor thread can emit alerts (avoids dropped live events).
    run_server_background(host=host, port=port, dashboard_state=_web_state)
    if not wait_for_server_ready(host, port):
        console.print(f"[red]Dashboard failed to start on {_dashboard_url(host, port)}[/red]")
        console.print(
            "[yellow]The dashboard did not become ready in time — port may be in use "
            "or the server thread failed to start.[/yellow]"
        )
        console.print("[dim]Stop it, then retry:[/dim]")
        console.print("  pkill -f 'guardian.cli serve'")
        console.print(f"  # or: ss -tlnp | grep {port}")
        sys.exit(1)

    # Responder
    from guardian.engine.responder import AutoResponder
    if respond_live:
        console.print("[bold red]Active response LIVE mode enabled.[/bold red]")
        _responder = AutoResponder(dry_run=False, on_response=_on_response)
    elif respond:
        console.print("[yellow]Active response DRY RUN mode enabled.[/yellow]")
        _responder = AutoResponder(dry_run=True, on_response=_on_response)

    # Start defense modules
    from guardian.modules.log_analyzer import LogAnalyzer
    from guardian.modules.network_monitor import NetworkMonitor
    from guardian.modules.file_monitor import FileIntegrityMonitor, ProcessMonitor

    default_logs = [
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/secure", "/var/log/messages",
    ]
    logs = list(log_files) or [f for f in default_logs if Path(f).exists()]
    dirs = list(watch_dirs) or ["/etc", "/tmp", "/var/tmp"]
    existing_dirs = [d for d in dirs if Path(d).exists()]

    correlator = get_correlator(on_campaign=_on_campaign)
    modules_started: list[str] = []

    if logs:
        la = LogAnalyzer(logs, _store_alert)
        la.start()
        modules_started.append(f"Log monitor ({len(logs)} files)")

    if existing_dirs:
        fim = FileIntegrityMonitor(existing_dirs, _store_alert)
        pm = ProcessMonitor(_store_alert)
        fim.start()
        pm.start()
        modules_started.append(f"File/process monitor ({len(existing_dirs)} dirs)")

    net = NetworkMonitor(_store_alert, iface=iface)
    net.start()
    modules_started.append("Network monitor")
    modules_started.append("Threat correlator")

    if global_ticker:
        from guardian.intel.global_ticker import start_global_ticker
        start_global_ticker(_store_alert, interval_secs=global_interval)
        modules_started.append(f"Global threat ticker ({global_interval}s poll)")

    console.print("[bold green]Guardian is active.[/bold green]")
    for m in modules_started:
        console.print(f"  [green]✓[/green] {m}")
    url = _dashboard_url(host, port)
    try:
        from guardian.web.deploy import deployment_info
        dep = deployment_info(host, port)
        if dep["mode"] == "vps" and dep.get("public_host"):
            console.print(f"  [dim]Public URL:[/dim] {dep['public_url']}")
    except ImportError:
        pass
    console.print(
        f"\n  [bold]Dashboard:[/bold] [link={url}]{url}[/link]\n"
    )
    if open_browser:
        _open_browser(_dashboard_url(host, port))
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Shutting down...[/dim]")


# ─── helpers ─────────────────────────────────────────────────────────────────

def _load_engine(model: Optional[str]) -> None:
    from guardian.engine.slm import get_engine

    with console.status("[dim]Loading Phi-3-mini...[/dim]"):
        try:
            get_engine(model_path=model)
        except FileNotFoundError as e:
            console.print(f"[red]{e}[/red]")
            console.print("[yellow]Run: guardian download-model[/yellow]")
            sys.exit(1)
        except ImportError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
