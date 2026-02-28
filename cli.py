#!/usr/bin/env python3
"""
bugcrowd-hunter v2 - Automated Bug Bounty Recon CLI

New in v2:
  - HackerOne support alongside Bugcrowd
  - Full recon pipeline: subfinder/amass -> dnsx -> httpx -> nuclei
  - Discovered subdomains auto-fed back into the scan queue
  - Deduplicated findings stored in DB with severity tracking
  - Slack/Discord notifications on new findings
  - Per-program priority and exclusion management
  - report command: rich summary of all findings
  - watch command: continuous sync + scan loop
  - program command: manage individual program settings
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

from .scraper import BugcrowdScraper, HackerOneScraper, Program
from .state import StateManager
from .scanner import Scanner, check_tools, TOOLS
from .worker import WorkerPool, populate_scan_queue
from .notifier import Notifier

console = Console()

DEFAULT_DATA_DIR = Path.home() / ".bugcrowd-hunter"

DEFAULT_CONFIG = {
    "bugcrowd_session": "",
    "hackerone_token": "",
    "request_delay": 1.5,
    "workers": 5,
    "platforms": ["bugcrowd", "hackerone"],
    "notifications": {
        "min_severity": "low",
        "slack_webhook": "",
        "discord_webhook": "",
    },
    "tools": {
        "subfinder": {"rate_limit": 50, "timeout": 300},
        "amass":     {"timeout": 600},
        "dnsx":      {"rate_limit": 100, "timeout": 120},
        "httpx":     {"rate_limit": 50, "timeout": 300},
        "gau":       {"timeout": 180},
        "nuclei": {
            "rate_limit": 25,
            "timeout": 600,
            "severity": ["low", "medium", "high", "critical"],
            "templates": ["cves", "exposures", "misconfiguration", "vulnerabilities"],
        },
    },
    "tool_delays": {
        "subfinder": 1.0,
        "amass":     2.0,
        "dnsx":      0.5,
        "httpx":     0.5,
        "gau":       1.0,
        "nuclei":    2.0,
    },
}

SEVERITY_STYLE = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        console.print(f"[dim]Created default config at {config_path}[/]")
    with config_path.open() as f:
        cfg = json.load(f)
    _deep_merge(cfg, DEFAULT_CONFIG)
    return cfg


def _deep_merge(target: dict, defaults: dict):
    """Merge missing keys from defaults into target (non-destructive)."""
    for k, v in defaults.items():
        if k not in target:
            target[k] = v
        elif isinstance(v, dict) and isinstance(target[k], dict):
            _deep_merge(target[k], v)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), envvar="BC_HUNTER_DIR",
              show_default=True, help="Data directory for DB and results")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, data_dir, verbose):
    """Bug Bounty Hunter v2 -- automated recon across Bugcrowd and HackerOne."""
    setup_logging(verbose)
    data_dir = Path(data_dir)
    cfg = load_config(data_dir / "config.json")
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir
    ctx.obj["config"] = cfg
    ctx.obj["state"] = StateManager(data_dir / "state.db")
    ctx.obj["scanner"] = Scanner(data_dir / "results", config=cfg.get("tools", {}))
    ctx.obj["notifier"] = Notifier(cfg, data_dir / "logs")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--platform", "-P", type=click.Choice(["bugcrowd", "hackerone", "all"]),
              default="all", help="Which platform to sync")
@click.option("--program", "-p", default=None, help="Sync a single program by slug")
@click.pass_context
def sync(ctx, platform, program):
    """Sync programs and in-scope targets from Bugcrowd and/or HackerOne."""
    cfg = ctx.obj["config"]
    state: StateManager = ctx.obj["state"]
    platforms = ["bugcrowd", "hackerone"] if platform == "all" else [platform]

    total_programs = 0
    total_targets = 0

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Syncing...", total=None)

        if "bugcrowd" in platforms:
            bc_token = cfg.get("bugcrowd_session") or None
            bc = BugcrowdScraper(session_token=bc_token, delay=cfg.get("request_delay", 1.5))

            if program:
                p = Program(name=program, code=program,
                            url=f"https://bugcrowd.com/{program}", platform="bugcrowd")
                p.targets = bc.fetch_targets(p)
                _save_program(state, p)
                console.print(f"[green]Bugcrowd: {program} -> {len(p.targets)} targets[/]")
            else:
                for prog in bc.iter_programs():
                    progress.update(task, description=f"[bugcrowd] {prog.name}")
                    prog.targets = bc.fetch_targets(prog)
                    _save_program(state, prog)
                    total_programs += 1
                    total_targets += len(prog.targets)

        if "hackerone" in platforms and not program:
            h1_token = cfg.get("hackerone_token") or None
            h1 = HackerOneScraper(session_token=h1_token, delay=cfg.get("request_delay", 1.5))
            for prog in h1.iter_programs():
                progress.update(task, description=f"[hackerone] {prog.name}")
                _save_program(state, prog)
                total_programs += 1
                total_targets += len(prog.targets)

    if not program:
        console.print(f"[green]Done. Synced {total_programs} programs, {total_targets} targets.[/]")


def _save_program(state: StateManager, prog: Program):
    state.upsert_program(prog.code, prog.name, prog.url, platform=prog.platform)
    for t in prog.targets:
        state.upsert_target(
            program=t.program, name=t.name, base_domain=t.base_domain,
            is_wildcard=t.is_wildcard, category=t.category, platform=t.platform,
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@cli.command(name="list")
@click.option("--platform", "-P", default=None, help="Filter by platform")
@click.option("--program", "-p", default=None, help="Filter by program")
@click.option("--targets", "show_targets", is_flag=True, help="Show targets instead of programs")
@click.option("--wildcards", is_flag=True, help="Show only wildcard targets")
@click.option("--discovered", is_flag=True, help="Show auto-discovered subdomains only")
@click.pass_context
def list_cmd(ctx, platform, program, show_targets, wildcards, discovered):
    """List synced programs and their targets."""
    state: StateManager = ctx.obj["state"]

    if show_targets or program:
        # source filter: if --discovered flag set, show only discovered; otherwise show all
        source = "discovered" if discovered else None
        targets = state.get_targets(
            program=program, platform=platform,
            wildcard_only=wildcards, source=source,
        )
        table = Table(title="Targets", box=box.SIMPLE)
        table.add_column("Platform", style="dim")
        table.add_column("Program", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Type", style="dim")
        for t in targets:
            if t["is_wildcard"]:
                ttype = "[yellow]wildcard[/]"
            elif t["source"] == "discovered":
                ttype = "[blue]discovered[/]"
            else:
                ttype = "scope"
            table.add_row(t["platform"], t["program"], t["name"], ttype)
        console.print(table)
        console.print(f"[dim]{len(targets)} targets[/]")
    else:
        programs = state.get_programs(platform=platform)
        table = Table(title="Programs", box=box.SIMPLE)
        table.add_column("Platform", style="dim")
        table.add_column("Code", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Pri", justify="right")
        table.add_column("Targets", justify="right")
        table.add_column("Excl", justify="center")
        table.add_column("Last Synced", style="dim")
        for p in programs:
            count = state.count_targets(program=p["code"], platform=p["platform"])
            excl = "[red]Y[/]" if p["excluded"] else ""
            table.add_row(
                p["platform"], p["code"], p["name"],
                str(p["priority"]), str(count), excl,
                (p["last_synced"] or "")[:16],
            )
        console.print(table)
        console.print(f"[dim]{len(programs)} programs[/]")


# ---------------------------------------------------------------------------
# program -- manage individual program settings
# ---------------------------------------------------------------------------

@cli.group()
def program():
    """Manage individual program settings (priority, exclusions, notes)."""


@program.command(name="set")
@click.argument("code")
@click.option("--platform", "-P", default="bugcrowd", show_default=True)
@click.option("--priority", type=int, default=None, help="1 (highest) to 10 (lowest)")
@click.option("--exclude", is_flag=True, default=False, help="Exclude from scanning")
@click.option("--include", is_flag=True, default=False, help="Re-include after exclusion")
@click.option("--notes", default=None, help="Free text notes")
@click.pass_context
def program_set(ctx, code, platform, priority, exclude, include, notes):
    """Set properties for a specific program."""
    state: StateManager = ctx.obj["state"]
    p = state.get_program(code, platform)
    if not p:
        console.print(f"[red]Program not found: {code} ({platform})[/]")
        return
    if priority is not None:
        state.set_program_priority(code, priority, platform)
        console.print(f"[green]Priority set to {priority}[/]")
    if exclude:
        state.set_program_excluded(code, True, platform)
        console.print(f"[yellow]{code} excluded from scanning[/]")
    if include:
        state.set_program_excluded(code, False, platform)
        console.print(f"[green]{code} re-included in scanning[/]")
    if notes is not None:
        state.set_program_notes(code, notes, platform)
        console.print(f"[green]Notes saved[/]")
    if not any([priority, exclude, include, notes]):
        # No flags given -- show current state
        console.print(f"Program: [cyan]{p['code']}[/] ({p['platform']})")
        console.print(f"  Priority: {p['priority']}")
        console.print(f"  Excluded: {'yes' if p['excluded'] else 'no'}")
        console.print(f"  Notes: {p['notes'] or '(none)'}")


# ---------------------------------------------------------------------------
# queue
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--program", "-p", default=None, help="Only queue for a specific program")
@click.option("--platform", "-P", default=None, help="Only queue for a specific platform")
@click.option("--tool", "-t", multiple=True, help="Only queue specific tools (repeatable)")
@click.option("--force", is_flag=True, help="Re-queue already-completed scans")
@click.pass_context
def queue(ctx, program, platform, tool, force):
    """Populate the scan queue for scope targets."""
    state: StateManager = ctx.obj["state"]
    tools = list(tool) or None
    n = populate_scan_queue(state, tools=tools, program=program, platform=platform, force=force)
    console.print(f"[green]Queued {n} scan jobs.[/]")
    _print_stats(state)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--workers", "-w", default=None, type=int, help="Number of parallel workers")
@click.option("--tool", "-t", default=None, help="Only run a specific tool")
@click.option("--max-jobs", default=None, type=int, help="Stop after N jobs")
@click.option("--nuclei-template", "-T", default=None,
              help="Run nuclei with a single template file/path instead of configured template categories")
@click.pass_context
def run(ctx, workers, tool, max_jobs, nuclei_template):
    """Run pending scans from the queue."""
    state: StateManager = ctx.obj["state"]
    scanner: Scanner = ctx.obj["scanner"]
    notifier: Notifier = ctx.obj["notifier"]
    cfg = ctx.obj["config"]

    available = check_tools()
    missing = [t for t, ok in available.items() if not ok]
    if missing:
        console.print(f"[yellow]Warning: not installed: {', '.join(missing)}[/]")

    pending_count = len(state.get_pending_scans(tool=tool, limit=100000))
    if pending_count == 0:
        console.print("[yellow]No pending scans. Run [bold]bch queue[/] first.[/]")
        return

    console.print(f"[cyan]{pending_count} pending scans. Starting...[/]")
    pool = WorkerPool(
        state=state,
        scanner=scanner,
        notifier=notifier,
        workers=workers or cfg.get("workers", 5),
        tool_delays=cfg.get("tool_delays", {}),
        nuclei_template=nuclei_template,
    )
    pool.run(max_jobs=max_jobs)
    _print_stats(state)


# ---------------------------------------------------------------------------
# watch -- continuous sync + scan loop
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--interval", default=3600, show_default=True,
              help="Seconds between sync+queue cycles")
@click.option("--workers", "-w", default=None, type=int)
@click.pass_context
def watch(ctx, interval, workers):
    """Continuously sync new programs/targets and run scans in a loop."""
    cfg = ctx.obj["config"]
    state: StateManager = ctx.obj["state"]
    scanner: Scanner = ctx.obj["scanner"]
    notifier: Notifier = ctx.obj["notifier"]

    console.print(f"[cyan]Watch mode: sync every {interval}s. Ctrl+C to stop.[/]")
    cycle = 0
    num_workers = workers or cfg.get("workers", 5)

    try:
        while True:
            cycle += 1
            console.print(f"\n[bold]Cycle {cycle} -- {datetime.utcnow().isoformat()[:19]}[/]")

            # Sync all platforms
            ctx.invoke(sync, platform="all", program=None)

            # Queue any new scope targets
            n = populate_scan_queue(state, force=False)
            console.print(f"[dim]{n} new jobs queued[/]")

            # Run until queue is drained
            pool = WorkerPool(
                state=state,
                scanner=scanner,
                notifier=notifier,
                workers=num_workers,
                tool_delays=cfg.get("tool_delays", {}),
            )
            pool.run()
            _print_stats(state)

            console.print(f"[dim]Sleeping {interval}s until next cycle...[/]")
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Watch mode stopped.[/]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def status(ctx):
    """Show scan queue stats and finding summary."""
    state: StateManager = ctx.obj["state"]
    _print_stats(state)

    summary = state.get_finding_summary()
    if summary:
        table = Table(title="Finding Summary", box=box.SIMPLE)
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = summary.get(sev, 0)
            if cnt:
                style = SEVERITY_STYLE.get(sev, "")
                table.add_row(Text(sev.upper(), style=style), str(cnt))
        console.print(table)


def _print_stats(state: StateManager):
    stats = state.get_scan_stats()
    if not stats:
        console.print("[dim]No scans in queue.[/]")
        return
    table = Table(title="Scan Queue", box=box.SIMPLE)
    table.add_column("Tool", style="cyan")
    for s in ["pending", "running", "done", "failed"]:
        table.add_column(s.capitalize(), justify="right")
    for tool_name in sorted(stats):
        row = [tool_name] + [str(stats[tool_name].get(s, 0))
                              for s in ["pending", "running", "done", "failed"]]
        table.add_row(*row)
    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--program", "-p", default=None, help="Filter by program")
@click.option("--platform", "-P", default=None, help="Filter by platform")
@click.option("--severity", "-s", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by severity")
@click.option("--json-out", is_flag=True, help="Output raw JSONL")
@click.option("--new-only", is_flag=True, help="Show only unnotified findings")
@click.pass_context
def report(ctx, program, platform, severity, json_out, new_only):
    """Show a report of all findings across programs."""
    state: StateManager = ctx.obj["state"]

    notified_filter = False if new_only else None
    findings = state.get_findings(
        program=program, platform=platform,
        severity=severity, notified=notified_filter,
    )

    if not findings:
        console.print("[dim]No findings match the filter.[/]")
        return

    if json_out:
        for f in findings:
            print(json.dumps(dict(f)))
        return

    table = Table(title=f"Findings ({len(findings)})", box=box.SIMPLE)
    table.add_column("Severity", width=10)
    table.add_column("Program", style="cyan")
    table.add_column("Platform", style="dim", width=10)
    table.add_column("Name", style="white")
    table.add_column("Target", style="dim")
    table.add_column("First Seen", style="dim", width=12)
    table.add_column("Count", justify="right", style="dim")

    for f in findings:
        sev = (f["severity"] or "info").lower()
        style = SEVERITY_STYLE.get(sev, "")
        table.add_row(
            Text(sev.upper(), style=style),
            f["program"], f["platform"], f["name"],
            f["target"][:60],
            (f["first_seen"] or "")[:10],
            str(f["count"]),
        )

    console.print(table)

    # Severity summary panel
    by_sev: dict = {}
    for f in findings:
        s = (f["severity"] or "info").lower()
        by_sev[s] = by_sev.get(s, 0) + 1

    summary_parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            style = SEVERITY_STYLE.get(sev, "")
            summary_parts.append(f"[{style}]{sev.upper()}: {by_sev[sev]}[/]")

    if summary_parts:
        console.print(Panel("  ".join(summary_parts), title="Summary"))


# ---------------------------------------------------------------------------
# results -- raw tool output viewer
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--program", "-p", required=True, help="Program code")
@click.option("--platform", "-P", default="bugcrowd", show_default=True)
@click.option("--tool", "-t", default=None, help="Filter by tool")
@click.option("--json-out", is_flag=True, help="Output raw JSONL")
@click.pass_context
def results(ctx, program, platform, tool, json_out):
    """View raw tool output for a program."""
    scanner: Scanner = ctx.obj["scanner"]
    results_dir = scanner.results_dir / platform / program

    if not results_dir.exists():
        console.print(f"[red]No results found for {program} ({platform})[/]")
        return

    tools_to_show = [tool] if tool else sorted(d.name for d in results_dir.iterdir() if d.is_dir())

    for t in tools_to_show:
        tool_dir = results_dir / t
        if not tool_dir.exists():
            continue
        console.print(f"\n[bold cyan]== {t.upper()} ==[/]")
        for result_file in sorted(tool_dir.glob("*.jsonl")):
            data = scanner.parse_results(result_file)
            if not data:
                continue
            if json_out:
                for item in data:
                    print(json.dumps(item))
            else:
                console.print(f"[dim]{result_file.name}[/] ({len(data)} results)")
                for item in data[:5]:
                    if t == "httpx":
                        line = f"  {item.get('status-code','?')} {item.get('url','?')} [{item.get('title','')}]"
                    elif t == "nuclei":
                        sev = item.get("info", {}).get("severity", "?")
                        name = item.get("info", {}).get("name", "?")
                        line = f"  [{sev}] {name} @ {item.get('host','?')}"
                    elif t in ("subfinder", "amass"):
                        line = f"  {item.get('host', item.get('name', '?'))}"
                    elif t == "dnsx":
                        line = f"  {item.get('host','?')} -> {item.get('a', item.get('cname', '?'))}"
                    else:
                        line = f"  {json.dumps(item)[:120]}"
                    console.print(line)
                if len(data) > 5:
                    console.print(f"  [dim]+{len(data) - 5} more (use --json-out for all)[/]")


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

@cli.command()
def tools():
    """Check which scanning tools are installed."""
    available = check_tools()
    table = Table(title="Tool Availability", box=box.SIMPLE)
    table.add_column("Tool", style="cyan")
    table.add_column("Stage", justify="right")
    table.add_column("Status")
    table.add_column("Applies To", style="dim")
    table.add_column("Description", style="dim")
    for tool_name, meta in TOOLS.items():
        ok = available.get(tool_name, False)
        status_str = "[green]Installed[/]" if ok else "[red]Missing[/]"
        table.add_row(
            tool_name, str(meta["stage"]), status_str,
            meta["applies_to"], meta["description"],
        )
    console.print(table)

    missing = [t for t, ok in available.items() if not ok]
    if missing:
        console.print("\n[yellow]Install missing tools (requires Go):[/]")
        install_cmds = {
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass":     "go install github.com/owasp-amass/amass/v4/...@master",
            "dnsx":      "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "httpx":     "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "gau":       "go install github.com/lc/gau/v2/cmd/gau@latest",
            "nuclei":    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        }
        for t in missing:
            if t in install_cmds:
                console.print(f"  [dim]{install_cmds[t]}[/]")


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

@cli.command(name="config")
@click.option("--edit", is_flag=True, help="Open config in $EDITOR")
@click.pass_context
def config_cmd(ctx, edit):
    """Show or edit configuration."""
    data_dir: Path = ctx.obj["data_dir"]
    config_path = data_dir / "config.json"
    if edit:
        import os
        import subprocess
        editor = os.environ.get("EDITOR", "notepad" if os.name == "nt" else "nano")
        subprocess.run([editor, str(config_path)])
    else:
        console.print_json(json.dumps(ctx.obj["config"], indent=2))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cli(obj={})


if __name__ == "__main__":
    main()
