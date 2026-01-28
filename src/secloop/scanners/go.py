"""Go vulnerability scanner using govulncheck."""

import subprocess
import json
from pathlib import Path
from typing import Optional

from .base import Scanner, Vulnerability


class GoScanner(Scanner):
    """Scanner for Go projects using govulncheck."""

    name = "govulncheck"
    ecosystem = "go"

    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan Go project for vulnerabilities."""
        vulnerabilities = []
        project_path = Path(project_path).resolve()

        cmd = [
            "govulncheck",
            "-json",
            "./...",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
            )

            # Parse NDJSON output (one JSON object per line)
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if "vulnerability" in data:
                        vuln = data["vulnerability"]
                        osv = vuln.get("osv", {})

                        # Get affected module info
                        modules = vuln.get("modules", [])
                        for mod in modules:
                            vulnerabilities.append(Vulnerability(
                                package=mod.get("path", ""),
                                version=mod.get("found_version", ""),
                                id=osv.get("id", ""),
                                fix_version=mod.get("fixed_version"),
                                severity=osv.get("severity"),
                                description=osv.get("summary"),
                            ))
                except json.JSONDecodeError:
                    continue

        except FileNotFoundError:
            pass

        return vulnerabilities

    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run Go tests."""
        cmd = command or "go test ./..."
        cmd_parts = cmd.split()

        try:
            result = subprocess.run(
                cmd_parts,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Tests timed out"
        except FileNotFoundError:
            return False, f"Command not found: {cmd_parts[0]}"

    def get_dependencies_file(self, project_path: Path) -> Optional[Path]:
        """Get go.mod path."""
        path = project_path / "go.mod"
        return path if path.exists() else None

    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Download Go dependencies."""
        try:
            result = subprocess.run(
                ["go", "mod", "download"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Download timed out"

    def is_available(self) -> bool:
        """Check if govulncheck is available."""
        import shutil
        return shutil.which("govulncheck") is not None
