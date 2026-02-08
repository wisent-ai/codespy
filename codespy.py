#!/usr/bin/env python3
"""
codespy - Fast offline code security scanner & quality analyzer.

Scans entire repositories for security vulnerabilities, code quality issues,
and generates actionable reports. Zero dependencies, runs offline.

Usage:
    python3 codespy.py [path] [options]

Examples:
    python3 codespy.py .                          # Scan current directory
    python3 codespy.py ./src --format json         # JSON output
    python3 codespy.py . --severity high           # Only high/critical issues
    python3 codespy.py . --fix                     # Show suggested fixes
    python3 codespy.py . --format sarif            # SARIF format for CI/CD
"""

import argparse
import json
import os
import re
import sys
import time
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "1.0.0"
__author__ = "Adam (ADAM) — Wisent AI Agent"


# ─── Configuration ──────────────────────────────────────────────────────────

# File extensions to scan by language
LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyw"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "ruby": {".rb"},
    "php": {".php"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".hpp", ".cc", ".cxx"},
    "csharp": {".cs"},
    "shell": {".sh", ".bash", ".zsh"},
    "yaml": {".yml", ".yaml"},
    "dockerfile": {"Dockerfile"},
    "terraform": {".tf"},
    "sql": {".sql"},
}

# Directories to always skip
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env", ".env",
    "vendor", "dist", "build", ".next", ".nuxt", "target",
    "coverage", ".coverage", "htmlcov", ".eggs", "*.egg-info",
}

MAX_FILE_SIZE = 1_000_000  # 1MB max per file


# ─── Data Models ────────────────────────────────────────────────────────────

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self == other or self < other


class Category(Enum):
    SECURITY = "security"
    SECRET = "secret"
    INJECTION = "injection"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    DEPRECATION = "deprecation"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply-chain"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    line_content: str
    suggestion: str = ""
    cwe_id: str = ""
    confidence: str = "high"  # high, medium, low

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }
        if self.cwe_id:
            d["cwe_id"] = self.cwe_id
        return d

    def to_sarif_result(self):
        """Convert to SARIF result format."""
        result = {
            "ruleId": self.rule_id,
            "level": self._sarif_level(),
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.file_path},
                    "region": {"startLine": self.line_number}
                }
            }],
        }
        if self.suggestion:
            result["fixes"] = [{
                "description": {"text": self.suggestion},
            }]
        return result

    def _sarif_level(self):
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping[self.severity]


@dataclass
class ScanResult:
    path: str
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    scan_duration_ms: float = 0
    findings: list = field(default_factory=list)
    language_stats: dict = field(default_factory=dict)

    @property
    def finding_count(self):
        return len(self.findings)

    @property
    def severity_counts(self):
        counts = Counter()
        for f in self.findings:
            counts[f.severity.value] += 1
        return dict(counts)

    @property
    def category_counts(self):
        counts = Counter()
        for f in self.findings:
            counts[f.category.value] += 1
        return dict(counts)

    def to_dict(self):
        return {
            "version": __version__,
            "path": self.path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_scanned": self.lines_scanned,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "total_findings": self.finding_count,
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "language_stats": self.language_stats,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_sarif(self):
        """Generate SARIF 2.1.0 output for CI/CD integration."""
        rules = {}
        results = []
        for f in self.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {"level": f._sarif_level()},
                }
                if f.cwe_id:
                    rules[f.rule_id]["properties"] = {"cwe": f.cwe_id}
            results.append(f.to_sarif_result())

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "codespy",
                        "version": __version__,
                        "informationUri": "https://github.com/wisent-ai/codespy",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }


# ─── Security Rules ────────────────────────────────────────────────────────

# Each rule: (rule_id, title, pattern, severity, category, description, suggestion, cwe_id, languages, confidence)
# languages=None means all languages

RULES = [
    # ── Hardcoded Secrets ──
    (
        "SEC001", "Hardcoded password",
        r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded password detected. Credentials should never be stored in source code.",
        "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "CWE-798", None, "high"
    ),
    (
        "SEC002", "Hardcoded API key",
        r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"][^'"]{8,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded API key or token detected.",
        "Use environment variables or a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC003", "Hardcoded secret/token",
        r"""(?:secret|token|auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*['"][^'"]{8,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded secret or authentication token detected.",
        "Rotate this secret immediately and use a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC004", "AWS access key",
        r"""(?:AKIA|ASIA)[A-Z0-9]{16}""",
        Severity.CRITICAL, Category.SECRET,
        "AWS access key ID detected in source code.",
        "Remove immediately, rotate the key, and use IAM roles or environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC005", "Private key material",
        r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""",
        Severity.CRITICAL, Category.SECRET,
        "Private key embedded in source code.",
        "Remove the private key and store it in a secure key management system.",
        "CWE-321", None, "high"
    ),
    (
        "SEC006", "Generic high-entropy secret",
        r"""(?:SECRET|PRIVATE|CREDENTIAL)[_A-Z]*\s*[=:]\s*['"][A-Za-z0-9+/=]{20,}['"]""",
        Severity.HIGH, Category.SECRET,
        "High-entropy string assigned to a secret-looking variable.",
        "Verify this isn't a real credential. Use environment variables for secrets.",
        "CWE-798", None, "medium"
    ),

    # ── Injection Vulnerabilities ──
    (
        "INJ001", "SQL injection risk",
        r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*\w+|['"].*\.format\()""",
        Severity.HIGH, Category.INJECTION,
        "Potential SQL injection via string formatting in query.",
        "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,))",
        "CWE-89", {"python"}, "high"
    ),
    (
        "INJ002", "Shell injection risk",
        r"""(?:subprocess\.(?:call|run|Popen)|os\.(?:system|popen))\s*\(.*shell\s*=\s*True""",
        Severity.HIGH, Category.INJECTION,
        "Shell command execution with shell=True enables injection attacks.",
        "Use subprocess with shell=False and pass arguments as a list.",
        "CWE-78", {"python"}, "high"
    ),
    (
        "INJ003", "Command injection via template",
        r"""os\.system\s*\(\s*(?:f['"]|['"].*%|['"].*\+|['"].*\.format)""",
        Severity.CRITICAL, Category.INJECTION,
        "OS command constructed from user-controlled input.",
        "Use subprocess.run() with shell=False and argument lists.",
        "CWE-78", {"python"}, "high"
    ),
    (
        "INJ004", "eval() usage",
        r"""\beval\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "eval() executes arbitrary code and is a major security risk.",
        "Use ast.literal_eval() for safe evaluation, or redesign to avoid eval entirely.",
        "CWE-95", {"python", "javascript", "typescript"}, "medium"
    ),
    (
        "INJ005", "Unsafe deserialization",
        r"""(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "Unsafe deserialization can execute arbitrary code.",
        "Use yaml.safe_load() or json.loads() instead.",
        "CWE-502", {"python"}, "high"
    ),
    (
        "INJ006", "innerHTML assignment",
        r"""\.innerHTML\s*=(?!=)""",
        Severity.MEDIUM, Category.INJECTION,
        "Direct innerHTML assignment can lead to XSS.",
        "Use textContent for text, or sanitize HTML with DOMPurify.",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
    (
        "INJ007", "SQL string concatenation",
        r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req\.|request\.|params\.|query\.)""",
        Severity.HIGH, Category.INJECTION,
        "SQL query built with string concatenation from request data.",
        "Use parameterized queries or an ORM.",
        "CWE-89", {"javascript", "typescript"}, "high"
    ),
    (
        "INJ008", "Exec/Function constructor",
        r"""new\s+Function\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "Function constructor creates code from strings, similar to eval().",
        "Refactor to use standard function definitions.",
        "CWE-95", {"javascript", "typescript"}, "high"
    ),
    (
        "INJ009", "Go SQL injection",
        r"""(?:db\.(?:Query|Exec|QueryRow))\s*\(\s*(?:fmt\.Sprintf|.*\+)""",
        Severity.HIGH, Category.INJECTION,
        "SQL query built with string formatting in Go.",
        "Use parameterized queries: db.Query(\"SELECT * FROM t WHERE id = $1\", id)",
        "CWE-89", {"go"}, "high"
    ),

    # ── Security Misconfigurations ──
    (
        "CFG001", "Debug mode enabled",
        r"""(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|'true'|"true")""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Debug mode appears to be enabled. This can expose sensitive information.",
        "Ensure debug mode is disabled in production.",
        "CWE-215", None, "medium"
    ),
    (
        "CFG002", "CORS wildcard",
        r"""(?:Access-Control-Allow-Origin|cors(?:_allow)?_origin[s]?)\s*[=:]\s*['"]\*['"]""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "CORS configured to allow all origins. This may expose APIs to unauthorized access.",
        "Restrict CORS to specific trusted domains.",
        "CWE-942", None, "medium"
    ),
    (
        "CFG003", "Insecure HTTP URL",
        r"""https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.com|example\.org)[a-zA-Z0-9.-]+\.[a-z]{2,}""",
        Severity.INFO, Category.CONFIGURATION,
        "HTTP URLs detected. Consider using HTTPS.",
        "Use HTTPS for all external communications.",
        "", None, "low"
    ),
    (
        "CFG004", "Disabled SSL verification",
        r"""verify\s*=\s*False""",
        Severity.HIGH, Category.SECURITY,
        "SSL certificate verification is disabled, enabling man-in-the-middle attacks.",
        "Enable SSL verification (verify=True) and use proper certificate management.",
        "CWE-295", {"python"}, "high"
    ),
    (
        "CFG005", "Insecure random for security",
        r"""(?:random\.(?:random|randint|choice|randrange))\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Standard random module is not cryptographically secure.",
        "Use secrets module for security-sensitive randomness: secrets.token_hex(), secrets.randbelow().",
        "CWE-338", {"python"}, "low"
    ),
    (
        "CFG006", "Weak hash algorithm",
        r"""(?:hashlib\.(?:md5|sha1)|MD5|SHA1)\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Weak hash algorithm (MD5/SHA1) detected. These are vulnerable to collisions.",
        "Use SHA-256 or stronger: hashlib.sha256().",
        "CWE-328", None, "medium"
    ),
    (
        "CFG007", "Permissive file permissions",
        r"""(?:chmod|os\.chmod)\s*\(.*0o?777""",
        Severity.HIGH, Category.CONFIGURATION,
        "File permissions set to 777 (world-readable/writable/executable).",
        "Use more restrictive permissions (e.g., 0o644 for files, 0o755 for directories).",
        "CWE-732", None, "high"
    ),

    # ── Code Quality ──
    (
        "QUA001", "TODO/FIXME/HACK comment",
        r"""#\s*(?:TODO|FIXME|HACK|XXX|WORKAROUND)\b""",
        Severity.INFO, Category.QUALITY,
        "Technical debt marker found.",
        "Address the TODO/FIXME before merging to main branch.",
        "", None, "high"
    ),
    (
        "QUA002", "Broad exception catch",
        r"""except\s*(?:Exception|BaseException|\s*:)""",
        Severity.LOW, Category.QUALITY,
        "Catching broad exceptions can hide bugs.",
        "Catch specific exceptions (e.g., ValueError, KeyError).",
        "CWE-396", {"python"}, "medium"
    ),
    (
        "QUA003", "Mutable default argument",
        r"""def\s+\w+\(.*=\s*(?:\[\]|\{\}|set\(\))""",
        Severity.MEDIUM, Category.QUALITY,
        "Mutable default argument in function definition. This is a common Python bug.",
        "Use None as default and initialize inside the function: def f(x=None): x = x or []",
        "CWE-665", {"python"}, "high"
    ),
    (
        "QUA004", "Loose equality (==) in JS",
        r"""[^=!<>]==[^=]""",
        Severity.LOW, Category.QUALITY,
        "Loose equality (==) can lead to unexpected type coercion.",
        "Use strict equality (===) instead.",
        "", {"javascript"}, "low"
    ),
    (
        "QUA005", "Console.log in production code",
        r"""console\.log\s*\(""",
        Severity.INFO, Category.QUALITY,
        "console.log() found. Remove before production deployment.",
        "Use a proper logging library or remove debug logging.",
        "", {"javascript", "typescript"}, "medium"
    ),
    (
        "QUA006", "Empty catch block",
        r"""(?:catch\s*\([^)]*\)\s*\{\s*\}|except.*:\s*(?:pass|\.\.\.)\s*$)""",
        Severity.MEDIUM, Category.QUALITY,
        "Empty catch/except block silently swallows errors.",
        "Log the error or handle it explicitly.",
        "CWE-390", None, "medium"
    ),

    # ── Performance ──
    (
        "PRF001", "Synchronous file I/O in async context",
        r"""(?:async\s+def\s+.*\n(?:.*\n)*?.*(?:open\(|os\.path|shutil\.))|(?:await.*(?:open\(|os\.path))""",
        Severity.LOW, Category.PERFORMANCE,
        "Synchronous file I/O in an async function blocks the event loop.",
        "Use aiofiles or run_in_executor for file I/O in async code.",
        "", {"python"}, "low"
    ),
    (
        "PRF002", "N+1 query pattern",
        r"""for\s+\w+\s+in\s+.*:\s*\n\s*.*(?:\.query|\.execute|\.find|\.get|SELECT)""",
        Severity.MEDIUM, Category.PERFORMANCE,
        "Potential N+1 query pattern: database query inside a loop.",
        "Use batch queries, JOINs, or prefetch_related/select_related.",
        "", None, "low"
    ),
    (
        "PRF003", "Regex in loop without compilation",
        r"""for\s+.*:\s*\n(?:.*\n)*?\s*re\.(?:search|match|findall|sub)\s*\(""",
        Severity.LOW, Category.PERFORMANCE,
        "Regex used inside a loop without pre-compilation.",
        "Compile the regex before the loop: pattern = re.compile(r'...'); pattern.search(text)",
        "", {"python"}, "low"
    ),

    # ── Supply Chain ──
    (
        "SUP001", "Unpinned dependency",
        r"""(?:pip install|gem install|npm install)\s+[a-zA-Z][\w-]*\s*$""",
        Severity.LOW, Category.SUPPLY_CHAIN,
        "Installing package without version pinning.",
        "Pin dependencies to specific versions for reproducible builds.",
        "CWE-1104", None, "low"
    ),

    # ── Dockerfile Security ──
    (
        "DOC001", "Running as root in Docker",
        r"""^(?!.*USER\s).*(?:CMD|ENTRYPOINT)""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Container may be running as root (no USER directive before CMD/ENTRYPOINT).",
        "Add a USER directive to run as non-root: USER nonroot",
        "CWE-250", {"dockerfile"}, "low"
    ),
    (
        "DOC002", "Latest tag in Docker FROM",
        r"""FROM\s+\w+(?::\s*latest|\s*$)""",
        Severity.LOW, Category.SUPPLY_CHAIN,
        "Using 'latest' or untagged base image makes builds non-reproducible.",
        "Pin to a specific version: FROM python:3.11-slim",
        "", {"dockerfile"}, "medium"
    ),

    # ── Terraform / IaC ──
    (
        "IAC001", "Public S3 bucket",
        r"""acl\s*=\s*['"]public-read['"]""",
        Severity.HIGH, Category.CONFIGURATION,
        "S3 bucket configured with public read access.",
        "Use 'private' ACL unless public access is explicitly required.",
        "CWE-284", {"terraform"}, "high"
    ),
    (
        "IAC002", "Open security group",
        r"""cidr_blocks\s*=\s*\[['"]0\.0\.0\.0/0['"]\]""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Security group open to all IPs (0.0.0.0/0).",
        "Restrict to specific IP ranges or use a VPN.",
        "CWE-284", {"terraform"}, "medium"
    ),
]


# ─── Scanner Engine ─────────────────────────────────────────────────────────

def detect_language_from_path(file_path: str) -> Optional[str]:
    """Detect language from file path/extension."""
    name = os.path.basename(file_path)
    ext = os.path.splitext(name)[1].lower()

    # Special filenames
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "dockerfile"
    if name in {"Makefile", "makefile", "GNUmakefile"}:
        return "shell"

    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        if ext in extensions:
            return lang
    return None


def should_skip_dir(dirname: str) -> bool:
    """Check if directory should be skipped."""
    return dirname in SKIP_DIRS or dirname.startswith(".")


def collect_files(path: str) -> list:
    """Collect all scannable files from a path."""
    files = []
    path = os.path.abspath(path)

    if os.path.isfile(path):
        lang = detect_language_from_path(path)
        if lang:
            files.append((path, lang))
        return files

    for root, dirs, filenames in os.walk(path):
        # Skip unwanted directories (modifying in-place for os.walk)
        dirs[:] = [d for d in dirs if not should_skip_dir(d)]

        for fname in filenames:
            fpath = os.path.join(root, fname)
            lang = detect_language_from_path(fpath)
            if lang:
                try:
                    size = os.path.getsize(fpath)
                    if size <= MAX_FILE_SIZE:
                        files.append((fpath, lang))
                except OSError:
                    pass
    return files


def scan_file(file_path: str, language: str, rules: list,
              min_severity: Severity = Severity.INFO) -> tuple:
    """Scan a single file and return findings and line count."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, IOError):
        return findings, 0

    lines = content.split("\n")
    line_count = len(lines)

    for (rule_id, title, pattern, severity, category, desc,
         suggestion, cwe_id, languages, confidence) in rules:

        # Skip rules not applicable to this language
        if languages and language not in languages:
            continue

        # Skip below minimum severity
        if severity < min_severity:
            continue

        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        for match in compiled.finditer(content):
            # Find line number
            line_num = content[:match.start()].count("\n") + 1
            line_content = lines[min(line_num - 1, len(lines) - 1)] if lines else ""

            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=severity,
                category=category,
                file_path=file_path,
                line_number=line_num,
                line_content=line_content,
                suggestion=suggestion,
                cwe_id=cwe_id,
                confidence=confidence,
            ))

    return findings, line_count


def run_scan(path: str, min_severity: Severity = Severity.INFO,
             rules: list = None) -> ScanResult:
    """Run a complete scan on a path."""
    start_time = time.time()
    result = ScanResult(path=os.path.abspath(path))

    if rules is None:
        rules = RULES

    files = collect_files(path)
    language_counts = Counter()
    language_lines = Counter()

    for file_path, language in files:
        findings, line_count = scan_file(file_path, language, rules, min_severity)

        # Make file paths relative to scan root
        rel_path = os.path.relpath(file_path, result.path)
        for f in findings:
            f.file_path = rel_path

        result.findings.extend(findings)
        result.files_scanned += 1
        result.lines_scanned += line_count
        language_counts[language] += 1
        language_lines[language] += line_count

    result.language_stats = {
        lang: {"files": language_counts[lang], "lines": language_lines[lang]}
        for lang in sorted(language_counts.keys())
    }

    result.scan_duration_ms = (time.time() - start_time) * 1000

    # Sort findings by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4,
    }
    result.findings.sort(key=lambda f: (severity_order[f.severity], f.file_path, f.line_number))

    return result


# ─── Output Formatters ──────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[1;31m",  # Bold Red
    "high": "\033[31m",        # Red
    "medium": "\033[33m",      # Yellow
    "low": "\033[36m",         # Cyan
    "info": "\033[37m",        # White/Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def format_terminal(result: ScanResult, show_fix: bool = False, use_color: bool = True) -> str:
    """Format scan results for terminal output."""
    lines = []
    c = SEVERITY_COLORS if use_color else {k: "" for k in SEVERITY_COLORS}
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    d = DIM if use_color else ""

    # Header
    lines.append(f"\n{b}codespy v{__version__}{r} — Code Security Scanner")
    lines.append(f"{d}{'─' * 60}{r}")
    lines.append(f"  Path:    {result.path}")
    lines.append(f"  Files:   {result.files_scanned} scanned, {result.files_skipped} skipped")
    lines.append(f"  Lines:   {result.lines_scanned:,}")
    lines.append(f"  Time:    {result.scan_duration_ms:.0f}ms")
    lines.append("")

    # Language breakdown
    if result.language_stats:
        lines.append(f"{b}Languages:{r}")
        for lang, stats in sorted(result.language_stats.items(),
                                   key=lambda x: x[1]["lines"], reverse=True):
            lines.append(f"  {lang:15s} {stats['files']:4d} files  {stats['lines']:>8,} lines")
        lines.append("")

    # Summary
    sc = result.severity_counts
    lines.append(f"{b}Findings:{r} {result.finding_count} total")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sc.get(sev, 0)
        if count > 0:
            lines.append(f"  {c[sev]}{sev.upper():10s}{r} {count}")
    lines.append("")

    if not result.findings:
        lines.append(f"  {b}No issues found.{r} Your code looks clean!")
        lines.append("")
        return "\n".join(lines)

    # Findings grouped by file
    lines.append(f"{d}{'─' * 60}{r}")
    findings_by_file = defaultdict(list)
    for f in result.findings:
        findings_by_file[f.file_path].append(f)

    for file_path, file_findings in sorted(findings_by_file.items()):
        lines.append(f"\n{b}{file_path}{r}")
        for f in file_findings:
            sev_str = f"{c[f.severity.value]}{f.severity.value.upper():8s}{r}"
            lines.append(f"  {sev_str}  L{f.line_number:<5d} [{f.rule_id}] {f.title}")
            lines.append(f"           {d}{f.line_content.strip()[:80]}{r}")
            if show_fix and f.suggestion:
                lines.append(f"           💡 {f.suggestion}")

    lines.append(f"\n{d}{'─' * 60}{r}")

    # Score
    score = compute_score(result)
    grade = score_to_grade(score)
    grade_color = c.get("info", "")
    if grade in ("A", "A+"):
        grade_color = "\033[32m" if use_color else ""
    elif grade in ("B", "B+"):
        grade_color = "\033[36m" if use_color else ""
    elif grade in ("C",):
        grade_color = "\033[33m" if use_color else ""
    else:
        grade_color = "\033[31m" if use_color else ""

    lines.append(f"\n{b}Security Score: {grade_color}{score}/100 (Grade: {grade}){r}")
    lines.append("")

    return "\n".join(lines)


def compute_score(result: ScanResult) -> int:
    """Compute a security score (0-100) from findings."""
    if result.files_scanned == 0:
        return 100

    # Deductions per severity
    deductions = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    total_deduction = sum(deductions[f.severity] for f in result.findings)

    # Normalize by codebase size (larger codebases get some leniency)
    size_factor = max(1, result.lines_scanned / 1000)
    adjusted_deduction = total_deduction / (1 + size_factor * 0.1)

    return max(0, min(100, round(100 - adjusted_deduction)))


def score_to_grade(score: int) -> str:
    """Convert score to letter grade."""
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B+"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0."""
    return json.dumps(result.to_sarif(), indent=2)


def format_markdown(result: ScanResult, show_fix: bool = False) -> str:
    """Format scan results as Markdown."""
    lines = []
    lines.append(f"# codespy Security Report")
    lines.append(f"")
    lines.append(f"**Path:** `{result.path}`  ")
    lines.append(f"**Files scanned:** {result.files_scanned}  ")
    lines.append(f"**Lines scanned:** {result.lines_scanned:,}  ")
    lines.append(f"**Scan time:** {result.scan_duration_ms:.0f}ms  ")
    lines.append(f"")

    score = compute_score(result)
    grade = score_to_grade(score)
    lines.append(f"## Security Score: {score}/100 (Grade: {grade})")
    lines.append(f"")

    # Severity summary
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    sc = result.severity_counts
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sc.get(sev, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            lines.append(f"| {emoji[sev]} {sev.upper()} | {count} |")
    lines.append(f"")

    if not result.findings:
        lines.append(f"**No issues found!** ✅")
        return "\n".join(lines)

    # Findings
    lines.append(f"## Findings")
    lines.append(f"")

    findings_by_file = defaultdict(list)
    for f in result.findings:
        findings_by_file[f.file_path].append(f)

    for file_path, file_findings in sorted(findings_by_file.items()):
        lines.append(f"### `{file_path}`")
        lines.append(f"")
        for f in file_findings:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            lines.append(f"- {emoji.get(f.severity.value, '')} **[{f.rule_id}] {f.title}** (L{f.line_number})")
            lines.append(f"  - {f.description}")
            if show_fix and f.suggestion:
                lines.append(f"  - 💡 **Fix:** {f.suggestion}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"*Generated by [codespy](https://github.com/wisent-ai/codespy) v{__version__}*")

    return "\n".join(lines)


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_severity(s: str) -> Severity:
    """Parse severity string to enum."""
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    s = s.lower().strip()
    if s in mapping:
        return mapping[s]
    raise ValueError(f"Invalid severity: {s}. Choose from: {', '.join(mapping.keys())}")


def main():
    parser = argparse.ArgumentParser(
        prog="codespy",
        description="Fast offline code security scanner & quality analyzer.",
        epilog="Built by Adam (ADAM) — https://github.com/wisent-ai/codespy",
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Path to scan (file or directory, default: current directory)"
    )
    parser.add_argument(
        "--format", "-f", choices=["terminal", "json", "sarif", "markdown"],
        default="terminal", help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--severity", "-s", default="info",
        help="Minimum severity to report: info, low, medium, high, critical"
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Show suggested fixes for each finding"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "--version", "-v", action="version",
        version=f"codespy {__version__}"
    )

    args = parser.parse_args()

    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Parse severity
    try:
        min_severity = parse_severity(args.severity)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Run scan
    result = run_scan(args.path, min_severity=min_severity)

    # Format output
    use_color = not args.no_color and args.format == "terminal" and sys.stdout.isatty()
    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    elif args.format == "markdown":
        output = format_markdown(result, show_fix=args.fix)
    else:
        output = format_terminal(result, show_fix=args.fix, use_color=use_color)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code: non-zero if critical/high findings
    critical_high = sum(1 for f in result.findings
                        if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
