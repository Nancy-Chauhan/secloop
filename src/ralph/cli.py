"""Ralph Loop CLI."""

import typer
from pathlib import Path
from typing import Optional
from rich.console import Console

from . import __version__
from .config import load_config, detect_ecosystem, save_config, DEFAULT_CONFIG
from .loop import RalphLoop
from .scanners import get_scanner
from . import ui

app = typer.Typer(
    name="ralph",
    help="Autonomous dependency vulnerability patcher using LLM loops",
    add_completion=False,
)
console = Console()


@app.command()
def run(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    ecosystem: Optional[str] = typer.Option(
        None,
        "--ecosystem", "-e",
        help="Project ecosystem (pip, npm, cargo). Auto-detected if not specified.",
    ),
    max_iterations: int = typer.Option(
        10,
        "--max-iterations", "-n",
        help="Maximum number of loop iterations",
    ),
    skip_permissions: bool = typer.Option(
        False,
        "--dangerously-skip-permissions",
        help="Skip Claude permission prompts (use with caution)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Scan for vulnerabilities without running the loop",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    Run the Ralph loop to fix dependency vulnerabilities.

    Example:
        ralph run ./my-project
        ralph run . --ecosystem pip --max-iterations 5
    """
    ui.print_banner()

    # Load config
    config = load_config(config_file, path)
    config["max_iterations"] = max_iterations
    config["project_path"] = str(path.resolve())

    # Detect ecosystem
    if ecosystem:
        config["ecosystem"] = ecosystem
    elif config.get("ecosystem") == "auto":
        detected = detect_ecosystem(path)
        if detected == "unknown":
            ui.print_error("Could not detect project ecosystem. Use --ecosystem to specify.")
            raise typer.Exit(1)
        config["ecosystem"] = detected
        ui.print_info(f"Detected ecosystem: {detected}")

    ui.print_config(config)

    # Get scanner
    try:
        scanner = get_scanner(config["ecosystem"])
    except ValueError as e:
        ui.print_error(str(e))
        raise typer.Exit(1)

    if not scanner.is_available():
        ui.print_error(f"Scanner '{scanner.name}' not found. Please install it first.")
        raise typer.Exit(1)

    # Dry run - just scan
    if dry_run:
        ui.print_step("Scanning for vulnerabilities...")
        vulns = scanner.scan(path)
        ui.print_scan_results([v.to_dict() for v in vulns], config["ecosystem"])

        if vulns:
            ui.print_info(f"Found {len(vulns)} vulnerabilities. Run without --dry-run to fix them.")
        raise typer.Exit(0 if not vulns else 1)

    # Run the loop
    loop = RalphLoop(
        project_path=path,
        ecosystem=config["ecosystem"],
        max_iterations=config["max_iterations"],
        completion_token=config.get("completion_token", "<COMPLETE>"),
        dangerously_skip_permissions=skip_permissions,
    )

    result = loop.run()

    if result.success:
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
    ),
    ecosystem: Optional[str] = typer.Option(
        None,
        "--ecosystem", "-e",
        help="Project ecosystem (pip, npm, cargo)",
    ),
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or count",
    ),
):
    """
    Scan project for vulnerabilities without fixing them.

    Example:
        ralph scan ./my-project
        ralph scan . --format json
    """
    # Detect ecosystem
    if not ecosystem:
        ecosystem = detect_ecosystem(path)
        if ecosystem == "unknown":
            ui.print_error("Could not detect project ecosystem. Use --ecosystem to specify.")
            raise typer.Exit(1)

    try:
        scanner = get_scanner(ecosystem)
    except ValueError as e:
        ui.print_error(str(e))
        raise typer.Exit(1)

    if not scanner.is_available():
        ui.print_error(f"Scanner '{scanner.name}' not found.")
        raise typer.Exit(1)

    vulns = scanner.scan(path)

    if output_format == "json":
        import json
        console.print(json.dumps([v.to_dict() for v in vulns], indent=2))
    elif output_format == "count":
        console.print(len(vulns))
    else:
        ui.print_scan_results([v.to_dict() for v in vulns], ecosystem)

    raise typer.Exit(0 if not vulns else 1)


@app.command()
def init(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing configuration",
    ),
):
    """
    Initialize Ralph configuration in a project.

    Example:
        ralph init ./my-project
    """
    config_path = path / "ralph.yaml"

    if config_path.exists() and not force:
        ui.print_warning(f"Configuration already exists: {config_path}")
        ui.print_info("Use --force to overwrite")
        raise typer.Exit(1)

    # Detect ecosystem
    ecosystem = detect_ecosystem(path)

    config = {
        "ecosystem": ecosystem if ecosystem != "unknown" else "auto",
        "max_iterations": 10,
        "completion_token": "<COMPLETE>",
    }

    save_config(config, config_path)
    ui.print_info(f"Created configuration: {config_path}")

    if ecosystem != "unknown":
        ui.print_info(f"Detected ecosystem: {ecosystem}")


@app.command()
def version():
    """Show version information."""
    console.print(f"ralph-loop v{__version__}")


def main():
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
