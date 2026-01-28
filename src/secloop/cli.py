"""SecLoop CLI - Autonomous security scanner & fixer."""

import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import box

from . import __version__
from .config import load_config, detect_ecosystem, save_config
from .loop import RalphLoop
from .scanners import get_scanner, SecretScanner, SASTScanner
from . import ui

app = typer.Typer(
    name="secloop",
    help="Autonomous security scanner & fixer using LLM loops",
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
        help="Project ecosystem (pip, npm, go, rust, ruby). Auto-detected if not specified.",
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
    Run the SecLoop to auto-fix dependency vulnerabilities.

    Example:
        secloop run ./my-project
        secloop run . --ecosystem pip --max-iterations 5
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
        help="Project ecosystem (pip, npm, go, rust, ruby)",
    ),
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or count",
    ),
):
    """
    Scan project for dependency vulnerabilities.

    Example:
        secloop scan ./my-project
        secloop scan . --format json
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
def secrets(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
    ),
    include_history: bool = typer.Option(
        False,
        "--history",
        help="Also scan git history for secrets",
    ),
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or count",
    ),
):
    """
    Scan project for hardcoded secrets (API keys, passwords, tokens).

    Example:
        secloop secrets ./my-project
        secloop secrets . --history
    """
    scanner = SecretScanner()

    if not scanner.is_available():
        ui.print_error("gitleaks not found. Install from: https://github.com/gitleaks/gitleaks")
        raise typer.Exit(1)

    if include_history:
        ui.print_step("Scanning git history for secrets...")
        findings = scanner.scan_git_history(path)
    else:
        ui.print_step("Scanning files for secrets...")
        findings = scanner.scan(path)

    if output_format == "json":
        import json
        console.print(json.dumps([s.to_dict() for s in findings], indent=2))
    elif output_format == "count":
        console.print(len(findings))
    else:
        _print_secrets_table(findings)

    raise typer.Exit(0 if not findings else 1)


def _print_secrets_table(findings):
    """Print secrets findings in table format."""
    if not findings:
        console.print("[green]No secrets found![/]")
        return

    table = Table(
        title=f"Found {len(findings)} Secrets",
        box=box.ROUNDED,
        border_style="red"
    )
    table.add_column("File", style="cyan")
    table.add_column("Line", style="yellow")
    table.add_column("Rule", style="red")
    table.add_column("Secret (redacted)", style="dim")

    for s in findings:
        table.add_row(
            s.file,
            str(s.line),
            s.rule,
            s.secret,
        )

    console.print(table)


@app.command()
def sast(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
    ),
    rules: str = typer.Option(
        "auto",
        "--rules", "-r",
        help="Semgrep rules to use (auto, p/security-audit, p/owasp-top-ten)",
    ),
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or count",
    ),
):
    """
    Run SAST analysis for code vulnerabilities (SQLi, XSS, etc).

    Example:
        secloop sast ./my-project
        secloop sast . --rules p/owasp-top-ten
    """
    scanner = SASTScanner()

    if not scanner.is_available():
        ui.print_error("No SAST tool found. Install semgrep or bandit.")
        ui.print_info("  pip install semgrep")
        ui.print_info("  pip install bandit")
        raise typer.Exit(1)

    ui.print_step("Running SAST analysis...")
    findings = scanner.scan(path)

    if output_format == "json":
        import json
        console.print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif output_format == "count":
        console.print(len(findings))
    else:
        _print_sast_table(findings)

    raise typer.Exit(0 if not findings else 1)


def _print_sast_table(findings):
    """Print SAST findings in table format."""
    if not findings:
        console.print("[green]No code vulnerabilities found![/]")
        return

    table = Table(
        title=f"Found {len(findings)} Code Issues",
        box=box.ROUNDED,
        border_style="yellow"
    )
    table.add_column("File:Line", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Rule", style="yellow")
    table.add_column("Message", style="white", max_width=50)

    for f in findings:
        sev_color = {"critical": "red", "error": "red", "warning": "yellow", "info": "blue"}.get(f.severity, "white")
        table.add_row(
            f"{f.file}:{f.line}",
            f"[{sev_color}]{f.severity}[/]",
            f.rule,
            f.message[:50] + "..." if len(f.message) > 50 else f.message,
        )

    console.print(table)


@app.command()
def audit(
    path: Path = typer.Argument(
        Path("."),
        help="Path to project directory",
    ),
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, sarif",
    ),
):
    """
    Run full security audit (dependencies + secrets + SAST).

    Example:
        secloop audit ./my-project
        secloop audit . --format sarif > results.sarif
    """
    ui.print_banner()
    results = {
        "dependencies": [],
        "secrets": [],
        "sast": [],
    }
    total_issues = 0

    # Dependencies
    ecosystem = detect_ecosystem(path)
    if ecosystem != "unknown":
        try:
            dep_scanner = get_scanner(ecosystem)
            if dep_scanner.is_available():
                ui.print_step(f"Scanning {ecosystem} dependencies...")
                vulns = dep_scanner.scan(path)
                results["dependencies"] = [v.to_dict() for v in vulns]
                total_issues += len(vulns)
                ui.print_scan_results(results["dependencies"], ecosystem)
        except ValueError:
            pass

    # Secrets
    secret_scanner = SecretScanner()
    if secret_scanner.is_available():
        ui.print_step("Scanning for secrets...")
        secrets = secret_scanner.scan(path)
        results["secrets"] = [s.to_dict() for s in secrets]
        total_issues += len(secrets)
        _print_secrets_table(secrets)

    # SAST
    sast_scanner = SASTScanner()
    if sast_scanner.is_available():
        ui.print_step("Running SAST analysis...")
        findings = sast_scanner.scan(path)
        results["sast"] = [f.to_dict() for f in findings]
        total_issues += len(findings)
        _print_sast_table(findings)

    # Summary
    console.print()
    console.print(f"[bold]Total issues found: {total_issues}[/]")

    if output_format == "json":
        import json
        console.print(json.dumps(results, indent=2))
    elif output_format == "sarif":
        console.print(_to_sarif(results))

    raise typer.Exit(0 if total_issues == 0 else 1)


def _to_sarif(results: dict) -> str:
    """Convert results to SARIF format."""
    import json

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecLoop",
                    "version": __version__,
                    "informationUri": "https://github.com/Nancy-Chauhan/secloop",
                }
            },
            "results": []
        }]
    }

    for vuln in results.get("dependencies", []):
        sarif["runs"][0]["results"].append({
            "ruleId": vuln.get("id", ""),
            "level": "error",
            "message": {"text": f"Vulnerable dependency: {vuln.get('package')}@{vuln.get('version')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "requirements.txt"}
                }
            }]
        })

    for secret in results.get("secrets", []):
        sarif["runs"][0]["results"].append({
            "ruleId": secret.get("rule", ""),
            "level": "error",
            "message": {"text": f"Hardcoded secret detected: {secret.get('rule')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": secret.get("file", "")},
                    "region": {"startLine": secret.get("line", 1)}
                }
            }]
        })

    for finding in results.get("sast", []):
        sarif["runs"][0]["results"].append({
            "ruleId": finding.get("rule", ""),
            "level": finding.get("severity", "warning"),
            "message": {"text": finding.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file", "")},
                    "region": {"startLine": finding.get("line", 1)}
                }
            }]
        })

    return json.dumps(sarif, indent=2)


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
    Initialize SecLoop configuration in a project.

    Example:
        secloop init ./my-project
    """
    config_path = path / "secloop.yaml"

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
        "scanners": {
            "dependencies": True,
            "secrets": True,
            "sast": True,
        },
    }

    save_config(config, config_path)
    ui.print_info(f"Created configuration: {config_path}")

    if ecosystem != "unknown":
        ui.print_info(f"Detected ecosystem: {ecosystem}")


@app.command()
def version():
    """Show version information."""
    console.print(f"secloop v{__version__}")


def main():
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
