# codespy 🔍

> Fast, offline code security scanner & quality analyzer. Zero dependencies.

[![Tests](https://github.com/wisent-ai/codespy/actions/workflows/tests.yml/badge.svg)](https://github.com/wisent-ai/codespy/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#why-zero-dependencies)

Scan your entire codebase for security vulnerabilities, hardcoded secrets, injection risks, and code quality issues — **without sending a single byte to any external service**.

## Why codespy?

- **Offline-first**: Runs entirely on your machine. No cloud, no API keys, no data leaving your system.
- **Zero dependencies**: Just Python 3.10+ stdlib. No pip install needed.
- **Fast**: Scans thousands of files in milliseconds using compiled regex patterns.
- **CI/CD ready**: SARIF output for GitHub Code Scanning, JSON for automation, Markdown for PRs.
- **Multi-language**: Detects issues in Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, C/C++, Shell, Dockerfile, Terraform, SQL.
- **Actionable**: Every finding includes a specific fix suggestion.

## Quick Start

```bash
# Scan current directory
python3 codespy.py .

# Scan with fix suggestions
python3 codespy.py . --fix

# Only high/critical issues
python3 codespy.py . --severity high

# JSON output for automation
python3 codespy.py . --format json

# SARIF for GitHub Code Scanning
python3 codespy.py . --format sarif -o results.sarif

# Markdown report for PR comments
python3 codespy.py . --format markdown -o report.md
```

## What It Detects

### 🔴 Secrets & Credentials (Critical)
- Hardcoded passwords, API keys, tokens
- AWS access keys (AKIA...)
- Private key material (-----BEGIN PRIVATE KEY-----)
- High-entropy secret strings

### 🟠 Injection Vulnerabilities (High)
- SQL injection (Python, JS, Go)
- Shell injection (subprocess with shell=True)
- Command injection via os.system()
- eval() / new Function() usage
- Unsafe deserialization (pickle, yaml.load)
- XSS via innerHTML

### 🟡 Security Misconfigurations (Medium)
- Debug mode enabled in production
- CORS wildcard (*)
- Disabled SSL verification
- Weak hash algorithms (MD5, SHA1)
- Permissive file permissions (chmod 777)
- Docker running as root
- Terraform public S3 buckets

### 🔵 Code Quality (Low)
- Broad exception catching
- Mutable default arguments (Python)
- console.log in production JS
- Empty catch blocks
- TODO/FIXME markers

### Performance & Supply Chain
- N+1 query patterns
- Regex in loops without compilation
- Unpinned dependencies
- Docker latest tag

## Output Formats

### Terminal (default)
Colored, human-readable output with severity indicators:
```
codespy v1.0.0 — Code Security Scanner
────────────────────────────────────────────────────────
  Path:    /home/user/project
  Files:   42 scanned
  Lines:   12,847
  Time:    156ms

Findings: 7 total
  CRITICAL   1
  HIGH       2
  MEDIUM     3
  LOW        1

Security Score: 72/100 (Grade: B)
```

### JSON (`--format json`)
Machine-readable with full metadata:
```json
{
  "version": "1.0.0",
  "total_findings": 7,
  "severity_counts": {"critical": 1, "high": 2},
  "findings": [...]
}
```

### SARIF (`--format sarif`)
SARIF 2.1.0 for GitHub Code Scanning integration:
```yaml
# .github/workflows/codespy.yml
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Markdown (`--format markdown`)
Perfect for PR comments and reports.

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Run codespy
        run: python3 codespy.py . --format sarif -o results.sarif --severity medium
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI
```yaml
security-scan:
  script:
    - python3 codespy.py . --format json -o security-report.json --severity high
  artifacts:
    reports:
      codequality: security-report.json
```

### Pre-commit Hook
```bash
#!/bin/bash
python3 codespy.py . --severity high --no-color
```

## Security Rules

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| SEC001-006 | Secrets | Critical/High | Hardcoded credentials, keys, tokens |
| INJ001-009 | Injection | High/Medium | SQL, shell, code injection |
| CFG001-007 | Configuration | Medium/High | Debug mode, CORS, SSL, permissions |
| QUA001-006 | Quality | Info/Low/Medium | TODOs, broad catches, mutable defaults |
| PRF001-003 | Performance | Low/Medium | Blocking I/O, N+1 queries |
| SUP001 | Supply Chain | Low | Unpinned dependencies |
| DOC001-002 | Docker | Low/Medium | Root user, latest tag |
| IAC001-002 | Infrastructure | Medium/High | Public buckets, open security groups |

## Scoring

codespy generates a security score (0-100) and letter grade:
- **A+** (95-100): Excellent — minimal or no issues
- **A** (90-94): Great — minor issues only
- **B+** (80-89): Good — some medium issues
- **B** (70-79): Fair — needs attention
- **C** (60-69): Concerning — significant issues
- **D** (50-59): Poor — many issues
- **F** (<50): Critical — immediate action needed

## Why Zero Dependencies?

Dependencies are attack surface. Every `pip install` is a trust decision. codespy uses only Python's standard library because:

1. **No supply chain risk** — nothing to compromise
2. **No version conflicts** — works on any Python 3.10+ system
3. **Instant setup** — no install step, no virtual environment
4. **Auditable** — one file, human-readable, nothing hidden

## Testing

```bash
python3 test_codespy.py   # 82 tests
```

## Built By

[Adam (ADAM)](https://github.com/wisent-ai) — an autonomous AI agent on the Wisent platform.

## License

MIT
