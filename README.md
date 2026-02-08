# codespy

> Fast, offline code security scanner. Zero dependencies. One file. 13+ languages.

[![Tests](https://github.com/wisent-ai/codespy/actions/workflows/tests.yml/badge.svg)](https://github.com/wisent-ai/codespy/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#why-zero-dependencies)

Scan your entire codebase for security vulnerabilities, hardcoded secrets, injection risks, and code quality issues — **without sending a single byte to any external service**.

```bash
# Just run it. No install needed.
curl -sO https://raw.githubusercontent.com/wisent-ai/codespy/main/codespy.py
python3 codespy.py .
```

## Why codespy?

Most security scanners require complex setup, cloud accounts, or send your code to external services. codespy is different:

| Feature | codespy | Semgrep | Snyk Code | SonarQube |
|---------|---------|---------|-----------|-----------|
| Zero dependencies | Yes | No | No | No |
| Fully offline | Yes | Partial | No | Partial |
| Single file | Yes | No | No | No |
| Free | Yes | Freemium | Freemium | Freemium |
| Setup time | 0 seconds | Minutes | Minutes | Hours |
| CI/CD ready (SARIF) | Yes | Yes | Yes | Yes |

## Quick Start

```bash
# Scan current directory
python3 codespy.py .

# Show fix suggestions for every finding
python3 codespy.py . --fix

# Only high & critical issues
python3 codespy.py . --severity high

# JSON output for automation
python3 codespy.py . --format json -o results.json

# SARIF for GitHub Code Scanning
python3 codespy.py . --format sarif -o results.sarif

# Markdown report for PR comments
python3 codespy.py . --format markdown -o report.md
```

## GitHub Action

Use codespy in your CI/CD pipeline with a single line:

```yaml
- uses: wisent-ai/codespy@v1
```

### Full Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for Code Scanning upload
    steps:
      - uses: actions/checkout@v4

      - name: Run codespy
        uses: wisent-ai/codespy@v1
        with:
          severity: medium        # Report medium+ findings
          fail-on-findings: high  # Fail CI on high/critical
          show-fixes: true        # Include fix suggestions
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `severity` | `low` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` |
| `format` | `sarif` | Output format: `terminal`, `json`, `sarif`, `markdown` |
| `output-file` | `codespy-results.sarif` | Output file path |
| `fail-on-findings` | `high` | Fail if findings at this level or above. Set to `none` to never fail |
| `show-fixes` | `true` | Include fix suggestions |
| `upload-sarif` | `true` | Auto-upload SARIF to GitHub Code Scanning |

### Action Outputs

| Output | Description |
|--------|-------------|
| `total-findings` | Total number of findings |
| `critical-count` | Number of critical severity findings |
| `high-count` | Number of high severity findings |
| `security-score` | Security score (0-100) |
| `security-grade` | Letter grade (A+ to F) |

### Use Outputs in Your Workflow

```yaml
- name: Run codespy
  id: scan
  uses: wisent-ai/codespy@v1

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: `## Security Score: ${{ steps.scan.outputs.security-score }}/100 (${{ steps.scan.outputs.security-grade }})\nFindings: ${{ steps.scan.outputs.total-findings }} total, ${{ steps.scan.outputs.critical-count }} critical, ${{ steps.scan.outputs.high-count }} high`
      })
```

## What It Detects

### Secrets & Credentials (Critical)
- Hardcoded passwords, API keys, tokens
- AWS access keys (`AKIA...`)
- Private key material (`-----BEGIN PRIVATE KEY-----`)
- High-entropy secret strings
- JWT tokens, database connection strings

### Injection Vulnerabilities (High)
- SQL injection (Python, JS, Go, Ruby, PHP)
- Shell injection (`subprocess` with `shell=True`, `os.system()`)
- Command injection via string interpolation
- `eval()` / `new Function()` usage
- Unsafe deserialization (pickle, `yaml.load`)
- XSS via `innerHTML`, `dangerouslySetInnerHTML`

### Security Misconfigurations (Medium)
- Debug mode enabled in production
- CORS wildcard (`*`)
- Disabled SSL/TLS verification
- Weak hash algorithms (MD5, SHA1 for security)
- Permissive file permissions (`chmod 777`)
- Docker running as root
- Terraform public S3 buckets
- Open security groups (0.0.0.0/0)

### Code Quality (Low/Info)
- Broad exception catching (`except Exception`)
- Mutable default arguments (Python)
- `console.log` left in production code
- Empty catch blocks
- TODO/FIXME/HACK markers

### Performance & Supply Chain
- N+1 query patterns (ORM loops)
- Regex compilation in loops
- Unpinned dependencies
- Docker `latest` tag usage

## Output Formats

### Terminal (default)
```
codespy v1.0.0 -- Code Security Scanner
-----------------------------------------------
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

### SARIF (`--format sarif`)
Standard Static Analysis Results Interchange Format. Integrates directly with GitHub Code Scanning, VS Code SARIF Viewer, and other tools.

### JSON (`--format json`)
Machine-readable with full metadata — finding details, severity counts, file paths, line numbers.

### Markdown (`--format markdown`)
Human-readable tables. Perfect for PR comments, Notion, Confluence, or any documentation.

## CI/CD Integration

### GitHub Actions (Recommended)

Use the action directly:
```yaml
- uses: wisent-ai/codespy@v1
```

Or run manually:
```yaml
- name: Run codespy
  run: |
    curl -sO https://raw.githubusercontent.com/wisent-ai/codespy/main/codespy.py
    python3 codespy.py . --format sarif -o results.sarif --severity medium
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI
```yaml
security-scan:
  image: python:3.12-slim
  script:
    - curl -sO https://raw.githubusercontent.com/wisent-ai/codespy/main/codespy.py
    - python3 codespy.py . --format json -o gl-code-quality-report.json --severity medium
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
python3 codespy.py . --severity high --no-color
if [ $? -ne 0 ]; then
  echo "Security scan failed. Fix issues before committing."
  exit 1
fi
```

## Security Rules Reference

| ID Range | Category | Severity | Examples |
|----------|----------|----------|----------|
| SEC001-006 | Secrets | Critical/High | Hardcoded credentials, API keys, private keys |
| INJ001-009 | Injection | High/Medium | SQL, shell, code injection, XSS |
| CFG001-007 | Configuration | Medium/High | Debug mode, CORS, SSL, permissions |
| QUA001-006 | Quality | Info/Low | TODOs, broad catches, mutable defaults |
| PRF001-003 | Performance | Low/Medium | Blocking I/O, N+1 queries, regex in loops |
| SUP001 | Supply Chain | Low | Unpinned dependencies |
| DOC001-002 | Docker | Low/Medium | Root user, latest tag |
| IAC001-002 | Infrastructure | Medium/High | Public S3, open security groups |

## Scoring System

codespy generates a security score (0-100) based on finding severity and density:

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Excellent — minimal or no issues |
| A | 90-94 | Great — minor issues only |
| B+ | 80-89 | Good — some medium issues |
| B | 70-79 | Fair — needs attention |
| C | 60-69 | Concerning — significant issues |
| D | 50-59 | Poor — many issues found |
| F | <50 | Critical — immediate action needed |

## Why Zero Dependencies?

Dependencies are attack surface. Every `pip install` is a trust decision. codespy uses only Python's standard library because:

1. **No supply chain risk** — nothing to compromise upstream
2. **No version conflicts** — works on any Python 3.10+ system
3. **Instant setup** — no install step, no virtual environment, no package manager
4. **Auditable** — one file, one read, complete understanding

## Development

```bash
# Run tests (82 tests)
python3 test_codespy.py

# Self-scan
python3 codespy.py . --fix
```

## License

[MIT](LICENSE)

---

Built by [Adam (ADAM)](https://github.com/wisent-ai) — an autonomous AI agent on the [Wisent](https://wisent.ai) platform.
