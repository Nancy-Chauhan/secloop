"""Security scanners for different ecosystems and vulnerability types."""

from .base import Scanner, Vulnerability
from .pip import PipScanner
from .npm import NpmScanner
from .go import GoScanner
from .rust import RustScanner
from .ruby import RubyScanner
from .secrets import SecretScanner, Secret
from .sast import SASTScanner, SASTFinding, SemgrepScanner, BanditScanner

__all__ = [
    "Scanner",
    "Vulnerability",
    "PipScanner",
    "NpmScanner",
    "GoScanner",
    "RustScanner",
    "RubyScanner",
    "SecretScanner",
    "Secret",
    "SASTScanner",
    "SASTFinding",
    "SemgrepScanner",
    "BanditScanner",
    "get_scanner",
    "get_all_scanners",
]


ECOSYSTEM_SCANNERS = {
    "pip": PipScanner,
    "python": PipScanner,
    "npm": NpmScanner,
    "node": NpmScanner,
    "go": GoScanner,
    "golang": GoScanner,
    "cargo": RustScanner,
    "rust": RustScanner,
    "ruby": RubyScanner,
    "gem": RubyScanner,
}


def get_scanner(ecosystem: str) -> Scanner:
    """Get dependency scanner for ecosystem."""
    scanner_class = ECOSYSTEM_SCANNERS.get(ecosystem.lower())
    if scanner_class is None:
        supported = ", ".join(sorted(set(ECOSYSTEM_SCANNERS.keys())))
        raise ValueError(f"Unsupported ecosystem: {ecosystem}. Supported: {supported}")

    return scanner_class()


def get_all_scanners() -> dict[str, Scanner]:
    """Get all available scanners."""
    return {
        "pip": PipScanner(),
        "npm": NpmScanner(),
        "go": GoScanner(),
        "rust": RustScanner(),
        "ruby": RubyScanner(),
    }


def detect_ecosystem(project_path) -> str:
    """Auto-detect project ecosystem from files."""
    from pathlib import Path
    project_path = Path(project_path)

    indicators = {
        "pip": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        "npm": ["package.json", "package-lock.json", "yarn.lock"],
        "go": ["go.mod", "go.sum"],
        "rust": ["Cargo.toml", "Cargo.lock"],
        "ruby": ["Gemfile", "Gemfile.lock"],
    }

    for ecosystem, files in indicators.items():
        for filename in files:
            if (project_path / filename).exists():
                return ecosystem

    return "unknown"
