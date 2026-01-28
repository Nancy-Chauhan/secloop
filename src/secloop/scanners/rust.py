"""Rust vulnerability scanner using cargo-audit."""

import subprocess
import json
from pathlib import Path
from typing import Optional

from .base import Scanner, Vulnerability


class RustScanner(Scanner):
    """Scanner for Rust projects using cargo-audit."""

    name = "cargo-audit"
    ecosystem = "cargo"

    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan Rust project for vulnerabilities."""
        vulnerabilities = []
        project_path = Path(project_path).resolve()

        cmd = [
            "cargo", "audit",
            "--json",
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

                for vuln in data.get("vulnerabilities", {}).get("list", []):
                    advisory = vuln.get("advisory", {})
                    pkg = vuln.get("package", {})

                    # Get fix version from versions info
                    versions = vuln.get("versions", {})
                    patched = versions.get("patched", [])
                    fix_version = patched[0] if patched else None

                    vulnerabilities.append(Vulnerability(
                        package=pkg.get("name", ""),
                        version=pkg.get("version", ""),
                        id=advisory.get("id", ""),
                        fix_version=fix_version,
                        severity=advisory.get("severity"),
                        description=advisory.get("title"),
                    ))

        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return vulnerabilities

    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run Cargo tests."""
        cmd = command or "cargo test"
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
        """Get Cargo.toml path."""
        path = project_path / "Cargo.toml"
        return path if path.exists() else None

    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Build Rust dependencies."""
        try:
            result = subprocess.run(
                ["cargo", "build"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Build timed out"

    def is_available(self) -> bool:
        """Check if cargo-audit is available."""
        import shutil
        return shutil.which("cargo-audit") is not None or shutil.which("cargo") is not None
