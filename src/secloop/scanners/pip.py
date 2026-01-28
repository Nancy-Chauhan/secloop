"""Pip/Python vulnerability scanner."""

import subprocess
import json
import re
from pathlib import Path
from typing import Optional

from .base import Scanner, Vulnerability


class PipScanner(Scanner):
    """Scanner for Python/pip projects."""

    name = "pip-audit"
    ecosystem = "pip"

    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan Python project for vulnerabilities using pip-audit."""
        vulnerabilities = []
        project_path = Path(project_path).resolve()

        # Build command - use requirements.txt if it exists
        req_file = project_path / "requirements.txt"
        if req_file.exists():
            cmd = ["pip-audit", "--format=json", "-r", str(req_file)]
        else:
            cmd = ["pip-audit", "--format=json"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # Parse JSON from stdout
            if result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict) and "dependencies" in data:
                    deps = data["dependencies"]
                elif isinstance(data, list):
                    deps = data
                else:
                    deps = []

                for dep in deps:
                    if isinstance(dep, dict) and "vulns" in dep:
                        for vuln in dep.get("vulns", []):
                            vulnerabilities.append(Vulnerability(
                                package=dep.get("name", ""),
                                version=dep.get("version", ""),
                                id=vuln.get("id", ""),
                                fix_version=", ".join(vuln.get("fix_versions", [])) or None,
                                description=vuln.get("description"),
                            ))
        except (json.JSONDecodeError, FileNotFoundError) as e:
            # Fall back to text parsing
            vulnerabilities = self._parse_text_output(project_path)

        return vulnerabilities

    def _parse_text_output(self, project_path: Path) -> list[Vulnerability]:
        """Parse pip-audit text output."""
        vulnerabilities = []
        project_path = Path(project_path).resolve()

        req_file = project_path / "requirements.txt"
        if req_file.exists():
            cmd = ["pip-audit", "-r", str(req_file)]
        else:
            cmd = ["pip-audit"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        output = result.stdout + result.stderr

        # Parse table format: Name Version ID Fix Versions
        pattern = r"^(\S+)\s+(\S+)\s+((?:CVE|PYSEC|GHSA)[\w-]+)\s+(.*)$"

        for line in output.split("\n"):
            line = line.strip()
            match = re.match(pattern, line)
            if match:
                vulnerabilities.append(Vulnerability(
                    package=match.group(1),
                    version=match.group(2),
                    id=match.group(3),
                    fix_version=match.group(4).strip() or None,
                ))

        return vulnerabilities

    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run pytest tests."""
        cmd = command or "pytest"
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
        """Get requirements.txt or pyproject.toml path."""
        for filename in ["requirements.txt", "pyproject.toml", "setup.py"]:
            path = project_path / filename
            if path.exists():
                return path
        return None

    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Install Python dependencies."""
        req_file = project_path / "requirements.txt"

        if req_file.exists():
            cmd = ["pip", "install", "-r", str(req_file)]
        elif (project_path / "pyproject.toml").exists():
            cmd = ["pip", "install", "-e", "."]
        else:
            return False, "No requirements.txt or pyproject.toml found"

        try:
            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"

    def is_available(self) -> bool:
        """Check if pip-audit is available."""
        import shutil
        return shutil.which("pip-audit") is not None
