"""Tests for the sample application."""

import pytest
from main import main, fetch_data, load_config
import tempfile
import os


def test_main_returns_true():
    """Test that main() returns True."""
    assert main() is True


def test_load_config_valid_yaml():
    """Test loading a valid YAML config."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("key: value\nnumber: 42\n")
        f.flush()
        config = load_config(f.name)
        os.unlink(f.name)

    assert config["key"] == "value"
    assert config["number"] == 42


def test_load_config_empty_file():
    """Test loading an empty YAML file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("")
        f.flush()
        config = load_config(f.name)
        os.unlink(f.name)

    assert config is None


def test_fetch_data_requires_url():
    """Test that fetch_data requires a URL argument."""
    with pytest.raises(TypeError):
        fetch_data()
