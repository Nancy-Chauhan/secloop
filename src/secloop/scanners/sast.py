"""SAST scanner using semgrep and bandit."""

import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class SASTFinding:
    """Represents a SAST finding."""
    file: str
    line: int
    rule: str
    message: str
    severity: str
    code_snippet: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix_suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "message": self.message,
            "severity": self.severity,
            "code_snippet": self.code_snippet,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "fix_suggestion": self.fix_suggestion,
        }


class SemgrepScanner:
    """SAST scanner using Semgrep."""

    name = "semgrep"

    def scan(
        self,
        project_path: Path,
        rules: str = "auto",
        severity_threshold: str = "warning"
    ) -> list[SASTFinding]:
        """Scan project for code vulnerabilities."""
        findings = []
        project_path = Path(project_path).resolve()

        # Build command
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--config", rules,
            str(project_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    findings.append(SASTFinding(
                        file=finding.get("path", ""),
                        line=finding.get("start", {}).get("line", 0),
                        rule=finding.get("check_id", ""),
                        message=finding.get("extra", {}).get("message", ""),
                        severity=finding.get("extra", {}).get("severity", "warning"),
                        code_snippet=finding.get("extra", {}).get("lines", ""),
                        cwe=self._extract_cwe(finding),
                        owasp=self._extract_owasp(finding),
                        fix_suggestion=finding.get("extra", {}).get("fix", ""),
                    ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return findings

    def _extract_cwe(self, finding: dict) -> Optional[str]:
        """Extract CWE from finding metadata."""
        metadata = finding.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [])
        return ", ".join(cwe) if isinstance(cwe, list) else cwe

    def _extract_owasp(self, finding: dict) -> Optional[str]:
        """Extract OWASP category from finding metadata."""
        metadata = finding.get("extra", {}).get("metadata", {})
        owasp = metadata.get("owasp", [])
        return ", ".join(owasp) if isinstance(owasp, list) else owasp

    def is_available(self) -> bool:
        """Check if semgrep is available."""
        import shutil
        return shutil.which("semgrep") is not None


class BanditScanner:
    """SAST scanner for Python using Bandit."""

    name = "bandit"

    def scan(
        self,
        project_path: Path,
        severity_threshold: str = "low"
    ) -> list[SASTFinding]:
        """Scan Python project for security issues."""
        findings = []
        project_path = Path(project_path).resolve()

        cmd = [
            "bandit",
            "-r",
            str(project_path),
            "-f", "json",
            "-ll",  # Low and above
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    findings.append(SASTFinding(
                        file=finding.get("filename", ""),
                        line=finding.get("line_number", 0),
                        rule=finding.get("test_id", ""),
                        message=finding.get("issue_text", ""),
                        severity=finding.get("issue_severity", "").lower(),
                        code_snippet=finding.get("code", ""),
                        cwe=finding.get("issue_cwe", {}).get("id"),
                        fix_suggestion=finding.get("more_info"),
                    ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return findings

    def is_available(self) -> bool:
        """Check if bandit is available."""
        import shutil
        return shutil.which("bandit") is not None


class SASTScanner:
    """Combined SAST scanner that uses the best available tool."""

    def __init__(self):
        self.semgrep = SemgrepScanner()
        self.bandit = BanditScanner()

    def scan(self, project_path: Path, language: Optional[str] = None) -> list[SASTFinding]:
        """Scan project using available SAST tools."""
        findings = []

        # Use semgrep if available (supports multiple languages)
        if self.semgrep.is_available():
            findings.extend(self.semgrep.scan(project_path))
        # Fall back to bandit for Python
        elif self.bandit.is_available() and (language == "python" or language is None):
            findings.extend(self.bandit.scan(project_path))

        return findings

    def is_available(self) -> bool:
        """Check if any SAST tool is available."""
        return self.semgrep.is_available() or self.bandit.is_available()
