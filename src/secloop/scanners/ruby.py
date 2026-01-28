"""Ruby vulnerability scanner using bundler-audit."""

import subprocess
import json
from pathlib import Path
from typing import Optional
import re

from .base import Scanner, Vulnerability


class RubyScanner(Scanner):
    """Scanner for Ruby projects using bundler-audit."""

    name = "bundler-audit"
    ecosystem = "ruby"

    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan Ruby project for vulnerabilities."""
        vulnerabilities = []
        project_path = Path(project_path).resolve()

        # Update advisory database first
        subprocess.run(
            ["bundle-audit", "update"],
            cwd=project_path,
            capture_output=True,
        )

        cmd = [
            "bundle-audit", "check",
            "--format", "json",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)

                for finding in data.get("results", []):
                    advisory = finding.get("advisory", {})
                    gem = finding.get("gem", {})

                    vulnerabilities.append(Vulnerability(
                        package=gem.get("name", ""),
                        version=gem.get("version", ""),
                        id=advisory.get("cve") or advisory.get("osvdb") or advisory.get("ghsa", ""),
                        fix_version=advisory.get("patched_versions", [""])[0] if advisory.get("patched_versions") else None,
                        severity=advisory.get("criticality"),
                        description=advisory.get("title"),
                    ))

        except (json.JSONDecodeError, FileNotFoundError):
            # Fall back to text parsing
            vulnerabilities = self._parse_text_output(project_path)

        return vulnerabilities

    def _parse_text_output(self, project_path: Path) -> list[Vulnerability]:
        """Parse bundler-audit text output."""
        vulnerabilities = []

        result = subprocess.run(
            ["bundle-audit", "check"],
            cwd=project_path,
            capture_output=True,
            text=True,
        )

        output = result.stdout + result.stderr

        # Parse text format
        # Name: actionpack
        # Version: 6.0.0
        # CVE: CVE-2020-8164
        current = {}
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("Name:"):
                current["package"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                current["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("CVE:") or line.startswith("GHSA:"):
                current["id"] = line.split(":", 1)[1].strip()
            elif line.startswith("Solution:"):
                match = re.search(r"upgrade to [~>]* ([\d.]+)", line.lower())
                if match:
                    current["fix_version"] = match.group(1)
            elif line.startswith("Title:"):
                current["description"] = line.split(":", 1)[1].strip()
            elif line == "" and current.get("package"):
                vulnerabilities.append(Vulnerability(
                    package=current.get("package", ""),
                    version=current.get("version", ""),
                    id=current.get("id", ""),
                    fix_version=current.get("fix_version"),
                    description=current.get("description"),
                ))
                current = {}

        return vulnerabilities

    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run Ruby tests."""
        cmd = command or "bundle exec rspec"
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
        """Get Gemfile path."""
        for filename in ["Gemfile.lock", "Gemfile"]:
            path = project_path / filename
            if path.exists():
                return path
        return None

    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Install Ruby dependencies."""
        try:
            result = subprocess.run(
                ["bundle", "install"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Install timed out"

    def is_available(self) -> bool:
        """Check if bundler-audit is available."""
        import shutil
        return shutil.which("bundle-audit") is not None or shutil.which("bundler-audit") is not None
