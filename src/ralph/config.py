"""Configuration handling for Ralph Loop."""

from pathlib import Path
from typing import Optional
import yaml
import toml

DEFAULT_CONFIG = {
    "max_iterations": 10,
    "completion_token": "<COMPLETE>",
    "ecosystem": "auto",
    "project_path": ".",
    "output_dir": ".ralph",
    "claude": {
        "model": "claude-sonnet-4-20250514",
        "dangerously_skip_permissions": False,
    },
    "scanners": {
        "pip": {
            "tool": "pip-audit",
            "test_command": "pytest",
        },
        "npm": {
            "tool": "npm audit",
            "test_command": "npm test",
        },
        "cargo": {
            "tool": "cargo audit",
            "test_command": "cargo test",
        },
    },
}

CONFIG_FILES = [
    "ralph.yaml",
    "ralph.yml",
    "ralph.toml",
    ".ralph.yaml",
    ".ralph.yml",
    ".ralph.toml",
]


def find_config_file(project_path: Path) -> Optional[Path]:
    """Find configuration file in project."""
    for name in CONFIG_FILES:
        config_path = project_path / name
        if config_path.exists():
            return config_path
    return None


def load_config(config_path: Optional[Path] = None, project_path: Optional[Path] = None) -> dict:
    """Load configuration from file or defaults."""
    config = DEFAULT_CONFIG.copy()

    if project_path is None:
        project_path = Path.cwd()

    # Find config file
    if config_path is None:
        config_path = find_config_file(project_path)

    if config_path and config_path.exists():
        file_config = _load_file(config_path)
        config = _merge_config(config, file_config)

    config["project_path"] = str(project_path)

    return config


def _load_file(path: Path) -> dict:
    """Load configuration from file."""
    content = path.read_text()

    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content) or {}
    elif path.suffix == ".toml":
        return toml.loads(content)
    else:
        return {}


def _merge_config(base: dict, override: dict) -> dict:
    """Deep merge configuration dictionaries."""
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_config(result[key], value)
        else:
            result[key] = value

    return result


def detect_ecosystem(project_path: Path) -> str:
    """Auto-detect project ecosystem."""
    indicators = {
        "pip": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        "npm": ["package.json", "package-lock.json", "yarn.lock"],
        "cargo": ["Cargo.toml", "Cargo.lock"],
        "go": ["go.mod", "go.sum"],
    }

    for ecosystem, files in indicators.items():
        for filename in files:
            if (project_path / filename).exists():
                return ecosystem

    return "unknown"


def save_config(config: dict, path: Path):
    """Save configuration to file."""
    if path.suffix in (".yaml", ".yml"):
        content = yaml.dump(config, default_flow_style=False)
    elif path.suffix == ".toml":
        content = toml.dumps(config)
    else:
        raise ValueError(f"Unsupported config format: {path.suffix}")

    path.write_text(content)
