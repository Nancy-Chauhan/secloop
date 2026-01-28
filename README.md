# SecLoop 🔐

Autonomous security scanner & fixer using LLM loops.

SecLoop automatically finds and fixes security vulnerabilities in your code using AI-powered iterative loops.

## Features

| Scanner | Description | Tool |
|---------|-------------|------|
| **Dependency Vulnerabilities** | CVEs in packages | pip-audit, npm audit |
| **Secret Detection** | Leaked API keys, passwords | gitleaks |
| **SAST** | Code vulnerabilities (SQLi, XSS) | semgrep, bandit |
| **License Compliance** | Problematic licenses | pip-licenses |

### Supported Ecosystems

- Python (pip)
- Node.js (npm)
- Go (govulncheck)
- Rust (cargo-audit)
- Ruby (bundler-audit)

## Installation

```bash
pip install secloop
```

Or from source:

```bash
git clone https://github.com/Nancy-Chauhan/secloop.git
cd secloop
pip install -e .
```

## Usage

### Scan for vulnerabilities

```bash
# Scan dependencies
secloop scan ./my-project

# Scan for secrets
secloop secrets ./my-project

# Run SAST analysis
secloop sast ./my-project

# Full security audit
secloop audit ./my-project
```

### Auto-fix vulnerabilities

```bash
# Fix dependency vulnerabilities using LLM loop
secloop run ./my-project

# With options
secloop run ./my-project --ecosystem pip --max-iterations 10
```

### Initialize config

```bash
secloop init ./my-project
```

## How It Works

SecLoop uses the "Ralph Loop" pattern - an iterative LLM loop that:

1. **Scan** - Detect vulnerabilities using security tools
2. **Analyze** - LLM understands the issues and plans fixes
3. **Fix** - Apply patches automatically
4. **Verify** - Re-scan to confirm fixes + run tests
5. **Repeat** - Until all issues resolved or max iterations

## Configuration

Create `secloop.yaml` in your project:

```yaml
ecosystem: auto
max_iterations: 10
completion_token: "<COMPLETE>"

scanners:
  dependencies: true
  secrets: true
  sast: true
  licenses: true

secrets:
  tool: gitleaks
  baseline: .gitleaks-baseline.json

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
      - run: pip install secloop
      - run: secloop audit . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## License

MIT
