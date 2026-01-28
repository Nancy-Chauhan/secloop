"""Secret detection scanner using gitleaks."""

import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class Secret:
    """Represents a detected secret."""
    file: str
    line: int
    rule: str
    secret: str  # Redacted
    commit: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "secret": self.secret,
            "commit": self.commit,
            "description": self.description,
        }


class SecretScanner:
    """Scanner for detecting hardcoded secrets using gitleaks."""

    name = "gitleaks"

    def scan(self, project_path: Path, baseline: Optional[Path] = None) -> list[Secret]:
        """Scan project for hardcoded secrets."""
        secrets = []
        project_path = Path(project_path).resolve()

        cmd = [
            "gitleaks",
            "detect",
            "--source", str(project_path),
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-git",  # Scan files, not git history
        ]

        if baseline and baseline.exists():
            cmd.extend(["--baseline-path", str(baseline)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # gitleaks outputs JSON array
            if result.stdout.strip():
                findings = json.loads(result.stdout)
                for finding in findings:
                    # Redact the actual secret
                    secret_val = finding.get("Secret", "")
                    redacted = secret_val[:4] + "*" * (len(secret_val) - 4) if len(secret_val) > 4 else "****"

                    secrets.append(Secret(
                        file=finding.get("File", ""),
                        line=finding.get("StartLine", 0),
                        rule=finding.get("RuleID", ""),
                        secret=redacted,
                        commit=finding.get("Commit"),
                        description=finding.get("Description"),
                    ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return secrets

    def scan_git_history(self, project_path: Path) -> list[Secret]:
        """Scan git history for secrets."""
        secrets = []
        project_path = Path(project_path).resolve()

        cmd = [
            "gitleaks",
            "detect",
            "--source", str(project_path),
            "--report-format", "json",
            "--report-path", "/dev/stdout",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                findings = json.loads(result.stdout)
                for finding in findings:
                    secret_val = finding.get("Secret", "")
                    redacted = secret_val[:4] + "*" * (len(secret_val) - 4) if len(secret_val) > 4 else "****"

                    secrets.append(Secret(
                        file=finding.get("File", ""),
                        line=finding.get("StartLine", 0),
                        rule=finding.get("RuleID", ""),
                        secret=redacted,
                        commit=finding.get("Commit"),
                        author=finding.get("Author"),
                        description=finding.get("Description"),
                    ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return secrets

    def is_available(self) -> bool:
        """Check if gitleaks is available."""
        import shutil
        return shutil.which("gitleaks") is not None

    def create_baseline(self, project_path: Path, output: Path) -> bool:
        """Create a baseline file for known secrets."""
        cmd = [
            "gitleaks",
            "detect",
            "--source", str(project_path),
            "--report-format", "json",
            "--report-path", str(output),
            "--no-git",
        ]

        try:
            subprocess.run(cmd, capture_output=True)
            return output.exists()
        except FileNotFoundError:
            return False
