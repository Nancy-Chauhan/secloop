"""Vulnerability scanners for different ecosystems."""

from .base import Scanner, Vulnerability
from .pip import PipScanner
from .npm import NpmScanner

__all__ = ["Scanner", "Vulnerability", "PipScanner", "NpmScanner", "get_scanner"]


def get_scanner(ecosystem: str) -> Scanner:
    """Get scanner for ecosystem."""
    scanners = {
        "pip": PipScanner,
        "npm": NpmScanner,
    }

    scanner_class = scanners.get(ecosystem)
    if scanner_class is None:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")

    return scanner_class()
