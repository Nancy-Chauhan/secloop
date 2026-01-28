# Ralph Loop

Autonomous dependency vulnerability patcher using LLM loops.

## Installation

```bash
pip install ralph-loop
```

## Usage

```bash
# Scan for vulnerabilities
ralph scan ./my-project

# Fix vulnerabilities automatically
ralph run ./my-project

# Initialize config
ralph init .
```

## How It Works

Ralph uses the "Ralph Loop" pattern - an iterative LLM loop that:

1. Scans dependencies for CVEs
2. Updates vulnerable packages
3. Runs tests to verify nothing broke
4. Repeats until all vulnerabilities are fixed

## Supported Ecosystems

- Python (pip-audit)
- Node.js (npm audit)
