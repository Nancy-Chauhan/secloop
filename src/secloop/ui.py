"""Rich UI components for Ralph Loop."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import box
from typing import Optional
import sys

console = Console()


def print_banner():
    """Print the SecLoop banner."""
    banner = """
[bold blue]╭─────────────────────────────────────────╮[/]
[bold blue]│[/]  [bold white]🔐 SECLOOP[/]                              [bold blue]│[/]
[bold blue]│[/]  [dim]Autonomous Security Scanner & Fixer[/]   [bold blue]│[/]
[bold blue]╰─────────────────────────────────────────╯[/]
"""
    console.print(banner)


def print_config(config: dict):
    """Print current configuration."""
    table = Table(title="Configuration", box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Project Path", str(config.get("project_path", ".")))
    table.add_row("Ecosystem", config.get("ecosystem", "auto"))
    table.add_row("Max Iterations", str(config.get("max_iterations", 10)))
    table.add_row("Completion Token", config.get("completion_token", "<COMPLETE>"))

    console.print(table)
    console.print()


def print_scan_results(vulnerabilities: list[dict], ecosystem: str):
    """Print vulnerability scan results."""
    if not vulnerabilities:
        console.print(Panel(
            "[bold green]No vulnerabilities found![/]",
            title="Scan Results",
            border_style="green"
        ))
        return

    table = Table(
        title=f"Found {len(vulnerabilities)} Vulnerabilities",
        box=box.ROUNDED,
        border_style="red"
    )
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("CVE/ID", style="red")
    table.add_column("Fix Version", style="green")

    for vuln in vulnerabilities:
        table.add_row(
            vuln.get("package", ""),
            vuln.get("version", ""),
            vuln.get("id", ""),
            vuln.get("fix_version", "N/A")
        )

    console.print(table)
    console.print()


def print_iteration_start(iteration: int, max_iterations: int):
    """Print iteration header."""
    console.print()
    console.rule(f"[bold yellow]Iteration {iteration}/{max_iterations}[/]")
    console.print()


def print_iteration_result(
    iteration: int,
    vulns_before: int,
    vulns_after: int,
    tests_passed: bool,
    status: str
):
    """Print iteration summary."""
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    # Vulnerabilities
    if vulns_after < vulns_before:
        vuln_style = "green"
        vuln_text = f"{vulns_after} [dim](↓{vulns_before - vulns_after})[/]"
    elif vulns_after > vulns_before:
        vuln_style = "red"
        vuln_text = f"{vulns_after} [dim](↑{vulns_after - vulns_before})[/]"
    else:
        vuln_style = "yellow"
        vuln_text = str(vulns_after)

    table.add_row("Vulnerabilities", f"[{vuln_style}]{vuln_text}[/]")

    # Tests
    test_text = "[green]PASSED[/]" if tests_passed else "[red]FAILED[/]"
    table.add_row("Tests", test_text)

    # Status
    status_style = "green" if status == "COMPLETE" else "yellow"
    table.add_row("Status", f"[{status_style}]{status}[/]")

    console.print(Panel(table, title=f"Iteration {iteration} Results"))


def print_success(iterations: int, vulns_fixed: int):
    """Print success message."""
    console.print()
    console.print(Panel(
        f"[bold green]All vulnerabilities patched![/]\n\n"
        f"Completed in [cyan]{iterations}[/] iteration(s)\n"
        f"Fixed [cyan]{vulns_fixed}[/] vulnerabilities",
        title="Success",
        border_style="green"
    ))


def print_failure(reason: str):
    """Print failure message."""
    console.print()
    console.print(Panel(
        f"[bold red]{reason}[/]",
        title="Failed",
        border_style="red"
    ))


def print_error(message: str):
    """Print error message."""
    console.print(f"[bold red]Error:[/] {message}", file=sys.stderr)


def print_warning(message: str):
    """Print warning message."""
    console.print(f"[bold yellow]Warning:[/] {message}")


def print_info(message: str):
    """Print info message."""
    console.print(f"[dim]ℹ[/] {message}")


def print_step(message: str):
    """Print step message."""
    console.print(f"[bold blue]→[/] {message}")


def create_progress() -> Progress:
    """Create a progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )


def confirm(message: str, default: bool = False) -> bool:
    """Ask for confirmation."""
    from rich.prompt import Confirm
    return Confirm.ask(message, default=default)
