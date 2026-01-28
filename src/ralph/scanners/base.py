"""Base scanner interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    package: str
    version: str
    id: str  # CVE or other identifier
    fix_version: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "id": self.id,
            "fix_version": self.fix_version,
            "severity": self.severity,
            "description": self.description,
        }


class Scanner(ABC):
    """Base class for vulnerability scanners."""

    name: str = "base"
    ecosystem: str = "unknown"

    @abstractmethod
    def scan(self, project_path: Path) -> list[Vulnerability]:
        """Scan project for vulnerabilities."""
        pass

    @abstractmethod
    def run_tests(self, project_path: Path, command: Optional[str] = None) -> tuple[bool, str]:
        """Run tests and return (passed, output)."""
        pass

    @abstractmethod
    def get_dependencies_file(self, project_path: Path) -> Optional[Path]:
        """Get path to dependencies file."""
        pass

    @abstractmethod
    def install_dependencies(self, project_path: Path) -> tuple[bool, str]:
        """Install dependencies and return (success, output)."""
        pass

    def is_available(self) -> bool:
        """Check if scanner tool is available."""
        import shutil
        return shutil.which(self.name) is not None
