<p align="center">
  <img src="https://img.icons8.com/fluency/96/security-checked.png" alt="SecLoop Logo" width="80"/>
</p>

<h1 align="center">SecLoop</h1>

<p align="center">
  <strong>Autonomous security scanner & auto-fixer powered by LLM loops</strong>
</p>

<p align="center">
  <a href="https://github.com/Nancy-Chauhan/secloop/actions"><img src="https://github.com/Nancy-Chauhan/secloop/workflows/Security%20Scan/badge.svg" alt="Build Status"></a>
  <a href="https://pypi.org/project/secloop/"><img src="https://img.shields.io/pypi/v/secloop.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/secloop/"><img src="https://img.shields.io/pypi/pyversions/secloop.svg" alt="Python versions"></a>
  <a href="https://github.com/Nancy-Chauhan/secloop/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Nancy-Chauhan/secloop.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#ci-cd-integration">CI/CD</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Why SecLoop?

Security vulnerabilities pile up. Dependency updates break things. Manual fixes take hours.

**SecLoop automates it all.** It scans your code, finds vulnerabilities, and uses AI to fix them automatically—while ensuring your tests still pass.

```bash
# Before: 14 vulnerabilities
$ secloop scan .
Found 14 vulnerabilities in 4 packages

# After: Fixed automatically
$ secloop run .
✓ All vulnerabilities patched in 1 iteration
```

## Features

### 🔍 Multi-Scanner Security Analysis

| Scanner | What it Detects | Tool |
|---------|-----------------|------|
| **Dependencies** | CVEs in packages | pip-audit, npm audit, cargo-audit |
| **Secrets** | API keys, passwords, tokens | gitleaks |
| **SAST** | SQL injection, XSS, command injection | semgrep, bandit |
| **Licenses** | Problematic licenses | pip-licenses |

### 🌐 Multi-Ecosystem Support

<table>
<tr>
<td align="center"><img src="https://img.icons8.com/color/48/python.png" width="32"/><br><b>Python</b></td>
<td align="center"><img src="https://img.icons8.com/color/48/nodejs.png" width="32"/><br><b>Node.js</b></td>
<td align="center"><img src="https://img.icons8.com/color/48/golang.png" width="32"/><br><b>Go</b></td>
<td align="center"><img src="https://img.icons8.com/external-tal-revivo-color-tal-revivo/48/external-rust-is-a-multi-paradigm-system-programming-language-logo-color-tal-revivo.png" width="32"/><br><b>Rust</b></td>
<td align="center"><img src="https://img.icons8.com/color/48/ruby-programming-language.png" width="32"/><br><b>Ruby</b></td>
</tr>
</table>

### 🤖 AI-Powered Auto-Fix

SecLoop uses the **Ralph Loop** pattern—an iterative LLM loop that:

1. **Scans** → Detects vulnerabilities using security tools
2. **Analyzes** → LLM understands issues and plans fixes
3. **Fixes** → Applies patches automatically
4. **Verifies** → Re-scans + runs tests to confirm
5. **Repeats** → Until all issues resolved

## Installation

### Using pip

```bash
pip install secloop
```

### From source

```bash
git clone https://github.com/Nancy-Chauhan/secloop.git
cd secloop
pip install -e .
```

### Required Tools

SecLoop wraps existing security tools. Install what you need:

```bash
# For Python projects
pip install pip-audit

# For secret detection
brew install gitleaks  # or: https://github.com/gitleaks/gitleaks

# For SAST analysis
pip install semgrep bandit
```

## Quick Start

```bash
# Scan for all security issues
secloop audit ./my-project

# Just check dependencies
secloop scan ./my-project

# Auto-fix vulnerabilities (requires Claude API key)
export ANTHROPIC_API_KEY=your-key
secloop run ./my-project
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `secloop scan` | Scan dependencies for CVEs |
| `secloop secrets` | Detect hardcoded secrets |
| `secloop sast` | Static analysis for code vulnerabilities |
| `secloop audit` | Run all scanners |
| `secloop run` | Auto-fix using LLM loops |
| `secloop init` | Create config file |

### Scan Dependencies

```bash
# Auto-detect ecosystem
secloop scan ./my-project

# Specify ecosystem
secloop scan ./my-project --ecosystem pip

# JSON output
secloop scan ./my-project --format json
```

### Detect Secrets

```bash
# Scan current files
secloop secrets ./my-project

# Include git history
secloop secrets ./my-project --history
```

### SAST Analysis

```bash
# Default rules
secloop sast ./my-project

# OWASP Top 10 rules
secloop sast ./my-project --rules p/owasp-top-ten
```

### Full Audit

```bash
# Table output
secloop audit ./my-project

# SARIF for CI/CD
secloop audit ./my-project --format sarif > results.sarif
```

### Auto-Fix Vulnerabilities

```bash
# Interactive mode
secloop run ./my-project

# Non-interactive (CI/CD)
secloop run ./my-project --dangerously-skip-permissions

# Limit iterations
secloop run ./my-project --max-iterations 5
```

## Configuration

Create `secloop.yaml` in your project root:

```yaml
# Ecosystem (auto-detected if not specified)
ecosystem: auto

# LLM loop settings
max_iterations: 10
completion_token: "<COMPLETE>"

# Enable/disable scanners
scanners:
  dependencies: true
  secrets: true
  sast: true
  licenses: false

# Secret detection settings
secrets:
  tool: gitleaks
  baseline: .gitleaks-baseline.json

# SAST settings
sast:
  tool: semgrep
  rules: auto
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install SecLoop
        run: pip install secloop pip-audit

      - name: Run security audit
        run: secloop audit . --format sarif > results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pip install secloop pip-audit
    - secloop audit .
  allow_failure: true
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secloop
        name: Security scan
        entry: secloop scan .
        language: system
        pass_filenames: false
```

## How It Works

### The Ralph Loop Pattern

```
┌─────────────────────────────────────────────────┐
│                                                 │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐   │
│   │  SCAN   │───▶│   FIX   │───▶│  TEST   │   │
│   └─────────┘    └─────────┘    └─────────┘   │
│        ▲                              │        │
│        │                              │        │
│        └──────────────────────────────┘        │
│                                                 │
│              Loop until clean                   │
└─────────────────────────────────────────────────┘
```

1. **Scan**: Run security tools (pip-audit, gitleaks, semgrep)
2. **Fix**: LLM analyzes findings and generates patches
3. **Test**: Run test suite to verify nothing broke
4. **Repeat**: Continue until all vulnerabilities fixed or max iterations

### Why Loops?

Traditional approaches fix one thing and often break another. The loop pattern ensures:

- ✅ Each fix is verified before moving on
- ✅ Breaking changes are caught immediately
- ✅ The process continues until truly complete
- ✅ Failures become data for the next iteration

## Supported Scanners

| Ecosystem | Dependency Scanner | Install |
|-----------|-------------------|---------|
| Python | pip-audit | `pip install pip-audit` |
| Node.js | npm audit | Built into npm |
| Go | govulncheck | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| Rust | cargo-audit | `cargo install cargo-audit` |
| Ruby | bundler-audit | `gem install bundler-audit` |

| Type | Scanner | Install |
|------|---------|---------|
| Secrets | gitleaks | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| SAST | semgrep | `pip install semgrep` |
| SAST | bandit | `pip install bandit` |

## Contributing

Contributions are welcome! Please read our contributing guidelines first.

```bash
# Clone the repo
git clone https://github.com/Nancy-Chauhan/secloop.git
cd secloop

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

### Adding a New Scanner

1. Create scanner class in `src/secloop/scanners/`
2. Inherit from `Scanner` base class
3. Implement `scan()`, `run_tests()`, `is_available()`
4. Register in `scanners/__init__.py`

## Roadmap

- [ ] Container image scanning (Trivy integration)
- [ ] Infrastructure as Code scanning (Terraform, CloudFormation)
- [ ] SBOM generation
- [ ] Web UI dashboard
- [ ] Slack/Discord notifications
- [ ] VS Code extension

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by the [Ralph Loop](https://ghuntley.com/loop/) pattern by Geoffrey Huntley
- Built with [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/)
- Security scanning powered by pip-audit, gitleaks, and semgrep

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
