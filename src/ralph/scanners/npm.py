"""NPM/Node.js vulnerability scanner."""

import subprocess
import json
from pathlib import Path
from typing import Optional

from .base import Scanner, Vulnerability


class NpmScanner(Scanner):
    """Scanner for Node.js/npm projects."""

    name = "npm"
    ecosystem = "npm"

    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan Node.js project for vulnerabilities using npm audit."""
        vulnerabilities = []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project_path,
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)

                # npm audit v2 format
                if "vulnerabilities" in data:
                    for pkg_name, vuln_data in data["vulnerabilities"].items():
                        vulnerabilities.append(Vulnerability(
                            package=pkg_name,
                            version=vuln_data.get("range", ""),
                            id=vuln_data.get("via", [{}])[0].get("url", "") if isinstance(vuln_data.get("via", []), list) and vuln_data.get("via") else "",
                            fix_version=vuln_data.get("fixAvailable", {}).get("version") if isinstance(vuln_data.get("fixAvailable"), dict) else None,
                            severity=vuln_data.get("severity"),
                        ))

                # npm audit v1 format
                elif "advisories" in data:
                    for advisory_id, advisory in data["advisories"].items():
                        vulnerabilities.append(Vulnerability(
                            package=advisory.get("module_name", ""),
                            version=advisory.get("vulnerable_versions", ""),
                            id=f"npm:{advisory_id}",
                            fix_version=advisory.get("patched_versions"),
                            severity=advisory.get("severity"),
                            description=advisory.get("title"),
                        ))

        except (json.JSONDecodeError, FileNotFoundError) as e:
            pass

        return vulnerabilities

    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run npm tests."""
        cmd = command or "npm test"
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
        """Get package.json path."""
        path = project_path / "package.json"
        return path if path.exists() else None

    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Install Node.js dependencies."""
        # Prefer npm ci for reproducible installs
        lock_file = project_path / "package-lock.json"
        cmd = ["npm", "ci"] if lock_file.exists() else ["npm", "install"]

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
        """Check if npm is available."""
        import shutil
        return shutil.which("npm") is not None
