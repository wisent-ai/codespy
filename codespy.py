#!/usr/bin/env python3
# Generated from codespy_core/ by tools/build_codespy.py; do not edit, render again.
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

Rendered from codespy_core/ by tools/build_codespy.py. Edit the package and render
again; an edit made here is overwritten by the next build.
"""


import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─── Scanner identity, the file types it reads, and the limits of one scan.

__version__ = "1.1.0"


__author__ = "Adam (ADAM) — Wisent AI Agent"


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


SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env", ".env",
    "vendor", "dist", "build", ".next", ".nuxt", "target",
    "coverage", ".coverage", "htmlcov", ".eggs", "*.egg-info",
}


MAX_FILE_SIZE = 1_000_000  # 1MB max per file


# ─── Severities, categories, findings, and the scan result reports are written from.

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
        """Every severity, present or not, so a report never has to guess a missing one."""
        counts = {severity.value: 0 for severity in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def category_counts(self):
        counts = Counter()
        for f in self.findings:
            counts[f.category.value] += 1
        return dict(counts)

    def to_dict(self):
        score = compute_score(self)
        grade = score_to_grade(score)
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
            "security_score": score,
            "security_grade": grade,
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


# ─── Detection rules, in the order codespy_core/rules declares.

RULES = [
    # ── secrets.CREDENTIALS ──
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
    # ── injection.CODE_EXECUTION ──
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
    # ── configuration.APPLICATION_SETTINGS ──
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
    # ── quality.MAINTAINABILITY ──
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
    # ── quality.PERFORMANCE ──
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
    # ── configuration.SUPPLY_CHAIN ──
    # ── Supply Chain ──
    (
        "SUP001", "Unpinned dependency",
        r"""(?:pip install|gem install|npm install)\s+[a-zA-Z][\w-]*\s*$""",
        Severity.LOW, Category.SUPPLY_CHAIN,
        "Installing package without version pinning.",
        "Pin dependencies to specific versions for reproducible builds.",
        "CWE-1104", None, "low"
    ),
    # ── configuration.CONTAINER_IMAGES ──
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
    # ── configuration.INFRASTRUCTURE ──
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
    # ── secrets.SERVICE_TOKENS ──
    # ── Additional Secret Patterns ──
    (
        "SEC007", "GitHub personal access token",
        r"""ghp_[A-Za-z0-9_]{36}""",
        Severity.CRITICAL, Category.SECRET,
        "GitHub personal access token detected in source code.",
        "Revoke this token at github.com/settings/tokens and use environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC008", "Slack webhook URL",
        r"""https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+""",
        Severity.HIGH, Category.SECRET,
        "Slack webhook URL detected in source code.",
        "Store webhook URLs in environment variables or a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC009", "Google API key",
        r"""AIza[0-9A-Za-z\-_]{35}""",
        Severity.HIGH, Category.SECRET,
        "Google API key detected in source code.",
        "Restrict the API key in Google Cloud Console and load from environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC010", "Stripe secret key",
        r"""(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}""",
        Severity.CRITICAL, Category.SECRET,
        "Stripe live secret key detected. This grants full access to payment processing.",
        "Revoke this key in the Stripe dashboard immediately and use environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC011", "Database connection string with credentials",
        r"""(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://\w+:[^@\s'"]{3,}@""",
        Severity.HIGH, Category.SECRET,
        "Database connection string with embedded credentials found in source code.",
        "Use environment variables for connection strings: os.environ['DATABASE_URL'].",
        "CWE-798", None, "high"
    ),
    (
        "SEC012", "Hardcoded Bearer/Authorization token",
        r"""['"](Bearer\s+[A-Za-z0-9\-_.]{20,})['"]""",
        Severity.HIGH, Category.SECRET,
        "Hardcoded Bearer token in source code.",
        "Load authentication tokens from environment variables or a secrets manager.",
        "CWE-798", None, "medium"
    ),
    # ── injection.REQUEST_FORGERY ──
    # ── SSRF (Server-Side Request Forgery) ──
    (
        "SSRF001", "Potential SSRF via requests library",
        r"""requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:f['"]|.*\+\s*(?:request|req|params|args)|.*\.format\()""",
        Severity.HIGH, Category.SECURITY,
        "HTTP request with user-controlled URL may enable Server-Side Request Forgery (SSRF).",
        "Validate and allowlist target URLs/hosts. Use a URL parser to verify the scheme and host.",
        "CWE-918", {"python"}, "medium"
    ),
    (
        "SSRF002", "Potential SSRF via fetch/axios",
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*(?:`.*\$\{|.*\+\s*(?:req\.|request\.|params\.|query\.|body\.))""",
        Severity.HIGH, Category.SECURITY,
        "HTTP request constructed from user input may enable SSRF attacks.",
        "Validate URLs against an allowlist of permitted hosts before making requests.",
        "CWE-918", {"javascript", "typescript"}, "medium"
    ),

    # ── Path Traversal ──
    (
        "PATH001", "Path traversal via user input",
        r"""(?:open|Path)\s*\(\s*(?:os\.path\.join\s*\(.*(?:request|req|params|args)|f['"].*(?:request|req|params|args))""",
        Severity.HIGH, Category.SECURITY,
        "File operation with user-controlled path may allow directory traversal attacks.",
        "Use os.path.realpath() and verify the resolved path is within the expected base directory.",
        "CWE-22", {"python"}, "medium"
    ),
    (
        "PATH002", "Path traversal in Node.js",
        r"""fs\.(?:readFile|writeFile|readdir|unlink|createReadStream|access)(?:Sync)?\s*\(\s*(?:req\.|request\.|params\.)""",
        Severity.HIGH, Category.SECURITY,
        "File system operation with user-controlled path enables path traversal.",
        "Use path.resolve() and verify the result starts with the intended base directory.",
        "CWE-22", {"javascript", "typescript"}, "medium"
    ),
    # ── injection.REDIRECTS ──
    # ── Open Redirect ──
    (
        "REDIR001", "Open redirect in Python web framework",
        r"""(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*(?:request\.|req\.|params\[|args\.)""",
        Severity.MEDIUM, Category.SECURITY,
        "Redirect using user-controlled input may allow open redirect attacks.",
        "Validate redirect targets against an allowlist of permitted URLs.",
        "CWE-601", {"python"}, "medium"
    ),
    (
        "REDIR002", "Open redirect in Express",
        r"""res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\[|req\.(?:query|params|body)\.)""",
        Severity.MEDIUM, Category.SECURITY,
        "Express redirect using user-supplied input enables open redirect.",
        "Validate redirect URLs against an allowlist of permitted paths or hosts.",
        "CWE-601", {"javascript", "typescript"}, "medium"
    ),
    # ── secrets.TOKEN_VERIFICATION ──
    # ── JWT / Authentication ──
    (
        "AUTH001", "JWT verification disabled",
        r"""(?:algorithms?\s*[=:]\s*\[?\s*['"]none['"]|jwt\.decode\s*\(.*(?:verify|options).*(?:False|false))""",
        Severity.CRITICAL, Category.SECURITY,
        "JWT verification disabled or 'none' algorithm accepted. Allows forged tokens.",
        "Always verify JWT signatures. Explicitly specify allowed algorithms: algorithms=['HS256'].",
        "CWE-347", None, "high"
    ),
    (
        "AUTH002", "Hardcoded JWT secret",
        r"""jwt\.(?:encode|sign)\s*\(.*['"][^'"]{8,}['"]""",
        Severity.HIGH, Category.SECRET,
        "JWT signed with a hardcoded secret key.",
        "Load the JWT secret from environment variables or a secrets manager.",
        "CWE-798", None, "medium"
    ),
    # ── configuration.CRYPTOGRAPHY ──
    # ── Cryptographic Issues ──
    (
        "CRYPTO001", "Weak cipher or ECB mode",
        r"""(?:DES|RC4|RC2|Blowfish|AES\.MODE_ECB|mode\s*=\s*['"]?ECB|createCipheriv\s*\(\s*['"](?:des|rc4|aes-\d+-ecb))""",
        Severity.HIGH, Category.SECURITY,
        "Weak cipher algorithm or insecure ECB block cipher mode detected.",
        "Use AES-256-GCM or AES-256-CBC with proper IV. Never use DES, RC4, or ECB mode.",
        "CWE-327", None, "high"
    ),
    (
        "CRYPTO002", "Hardcoded initialization vector",
        r"""(?:iv|nonce|IV|NONCE)\s*=\s*(?:b['"][^'"]{8,}['"]|bytes\(|b'\\x)""",
        Severity.HIGH, Category.SECURITY,
        "Hardcoded initialization vector (IV) makes encryption predictable.",
        "Generate a random IV for each encryption operation using os.urandom() or crypto.randomBytes().",
        "CWE-329", None, "medium"
    ),
    # ── injection.TEMPLATES ──
    # ── Template Injection (SSTI) ──
    (
        "SSTI001", "Server-side template injection",
        r"""render_template_string\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "render_template_string() renders templates from strings, enabling server-side template injection if user input is included.",
        "Use render_template() with static template files instead of render_template_string().",
        "CWE-1336", {"python"}, "medium"
    ),
    # ── injection.BROWSER_MARKUP ──
    # ── React / Frontend XSS ──
    (
        "REACT001", "dangerouslySetInnerHTML usage",
        r"""dangerouslySetInnerHTML""",
        Severity.MEDIUM, Category.INJECTION,
        "dangerouslySetInnerHTML bypasses React's built-in XSS protections.",
        "Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML.",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
    (
        "REACT002", "javascript: URI in href",
        r"""href\s*=\s*['"]javascript:""",
        Severity.HIGH, Category.INJECTION,
        "javascript: URIs in href attributes execute arbitrary code (XSS).",
        "Validate URLs and reject javascript: protocol. Allow only http: and https: schemes.",
        "CWE-79", {"javascript", "typescript"}, "high"
    ),
    (
        "JS001", "document.write() usage",
        r"""document\.write\s*\(""",
        Severity.MEDIUM, Category.INJECTION,
        "document.write() can introduce XSS vulnerabilities and blocks page rendering.",
        "Use DOM APIs (createElement, textContent) instead of document.write().",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
    # ── injection.WEB_FRAMEWORKS ──
    # ── Django-Specific ──
    (
        "DJANGO001", "Django mark_safe with variable input",
        r"""mark_safe\s*\(\s*(?:f['"]|.*\+|.*\.format\(|.*%)""",
        Severity.HIGH, Category.INJECTION,
        "mark_safe() with dynamic content bypasses Django's auto-escaping, enabling XSS.",
        "Use format_html() instead of mark_safe() with string formatting.",
        "CWE-79", {"python"}, "high"
    ),
    (
        "DJANGO002", "Django raw SQL query",
        r"""(?:\.raw|\.extra|RawSQL)\s*\(\s*(?:f['"]|['"].*\.format\()""",
        Severity.HIGH, Category.INJECTION,
        "Django raw SQL query with string formatting enables SQL injection.",
        "Use Django ORM or pass parameters: Model.objects.raw('SELECT ... WHERE id = %s', [id]).",
        "CWE-89", {"python"}, "high"
    ),

    # ── Flask-Specific ──
    (
        "FLASK001", "Flask SECRET_KEY hardcoded",
        r"""(?:app\.secret_key|config\s*\[\s*['"]SECRET_KEY['"]\s*\])\s*=\s*['"][^'"]+['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Flask SECRET_KEY is hardcoded. This compromises session security.",
        "Load SECRET_KEY from environment variable: app.secret_key = os.environ['SECRET_KEY'].",
        "CWE-798", {"python"}, "high"
    ),
    (
        "FLASK002", "Flask send_file path traversal",
        r"""send_file\s*\(\s*(?:request\.|os\.path\.join\s*\(.*request\.)""",
        Severity.HIGH, Category.SECURITY,
        "send_file() with user-controlled path enables arbitrary file read.",
        "Use send_from_directory() with a fixed base directory instead.",
        "CWE-22", {"python"}, "high"
    ),

    # ── Node.js / Express ──
    (
        "JS002", "Command injection via child_process",
        r"""child_process\.(?:exec|execSync)\s*\(\s*(?:`.*\$\{|.*\+\s*(?:req|request|params|query|body))""",
        Severity.CRITICAL, Category.INJECTION,
        "Command executed with user-controlled input enables remote code execution.",
        "Use execFile/execFileSync with arguments as an array. Never concatenate user input into commands.",
        "CWE-78", {"javascript", "typescript"}, "high"
    ),
    # ── configuration.JAVASCRIPT_RUNTIME ──
    (
        "JS003", "Node.js TLS verification disabled",
        r"""(?:NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized)\s*[=:]\s*(?:['"]?0['"]?|false)""",
        Severity.HIGH, Category.SECURITY,
        "TLS certificate verification disabled. Enables man-in-the-middle attacks.",
        "Enable TLS verification. Use proper CA certificates for self-signed certs.",
        "CWE-295", {"javascript", "typescript"}, "high"
    ),
    (
        "JS004", "Math.random() for security",
        r"""Math\.random\s*\(\s*\)""",
        Severity.MEDIUM, Category.SECURITY,
        "Math.random() is not cryptographically secure and should not be used for security.",
        "Use crypto.randomUUID(), crypto.getRandomValues(), or crypto.randomBytes().",
        "CWE-338", {"javascript", "typescript"}, "low"
    ),
    # ── configuration.PYTHON_RUNTIME ──
    # ── Python-Specific ──
    (
        "PY001", "Insecure temporary file creation",
        r"""(?:tempfile\.mktemp|os\.tempnam|os\.tmpnam)\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Insecure temporary file creation is vulnerable to race condition attacks.",
        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
        "CWE-377", {"python"}, "high"
    ),
    (
        "PY002", "Assert used for security validation",
        r"""assert\s+.*(?:is_authenticated|is_staff|is_superuser|has_perm|is_admin)""",
        Severity.HIGH, Category.SECURITY,
        "assert statements are removed when Python runs with -O flag. Never use for security checks.",
        "Use if/raise for security: if not user.is_authenticated: raise PermissionError().",
        "CWE-617", {"python"}, "medium"
    ),
    # ── injection.DESERIALIZATION ──
    (
        "PY003", "Unsafe marshal/shelve deserialization",
        r"""(?:marshal\.loads?|shelve\.open)\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "marshal and shelve can execute arbitrary code during deserialization.",
        "Use json.loads() for untrusted data. Only use marshal/shelve with trusted sources.",
        "CWE-502", {"python"}, "medium"
    ),
    # ── configuration.KUBERNETES ──
    # ── Kubernetes / Container Security ──
    (
        "K8S001", "Privileged Kubernetes container",
        r"""privileged\s*:\s*true""",
        Severity.CRITICAL, Category.CONFIGURATION,
        "Container running in privileged mode has full host access.",
        "Remove privileged: true. Use specific capabilities if needed.",
        "CWE-250", {"yaml"}, "high"
    ),
    (
        "K8S002", "Container running as root in Kubernetes",
        r"""runAsUser\s*:\s*0\b""",
        Severity.HIGH, Category.CONFIGURATION,
        "Kubernetes pod configured to run as root user.",
        "Set runAsNonRoot: true and specify a non-zero runAsUser in securityContext.",
        "CWE-250", {"yaml"}, "high"
    ),
    (
        "K8S003", "Kubernetes host namespace sharing",
        r"""(?:hostNetwork|hostPID|hostIPC)\s*:\s*true""",
        Severity.HIGH, Category.CONFIGURATION,
        "Pod shares the host's network/PID/IPC namespace, breaking container isolation.",
        "Remove hostNetwork/hostPID/hostIPC unless absolutely required.",
        "CWE-250", {"yaml"}, "high"
    ),
    # ── configuration.CONTAINER_BUILDS ──
    # ── Additional Dockerfile Rules ──
    (
        "DOC003", "Docker ADD instead of COPY",
        r"""\bADD\s+(?!https?://)""",
        Severity.LOW, Category.CONFIGURATION,
        "ADD instruction used instead of COPY. ADD can auto-extract archives and fetch URLs unexpectedly.",
        "Use COPY unless you specifically need ADD's tar extraction or URL fetching features.",
        "", {"dockerfile"}, "medium"
    ),
    (
        "DOC004", "Secret in Docker ARG/ENV",
        r"""(?:ARG|ENV)\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL)\w*)\b""",
        Severity.HIGH, Category.SECRET,
        "Secret passed via ARG or ENV in Dockerfile. ARG values are visible in docker history.",
        "Use Docker BuildKit secrets (--mount=type=secret) or runtime environment variables.",
        "CWE-798", {"dockerfile"}, "medium"
    ),
    (
        "DOC005", "Sensitive port exposed in Dockerfile",
        r"""EXPOSE\s+(?:22|3389|5432|3306|6379|27017|11211)\b""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Sensitive service port (SSH/DB/cache) exposed in Dockerfile.",
        "Avoid exposing database or management ports. Use Docker networks for inter-service communication.",
        "CWE-284", {"dockerfile"}, "medium"
    ),
    # ── configuration.MANAGED_DATABASES ──
    # ── Additional IaC Rules ──
    (
        "IAC003", "Publicly accessible RDS instance",
        r"""publicly_accessible\s*=\s*true""",
        Severity.HIGH, Category.CONFIGURATION,
        "RDS database instance is publicly accessible from the internet.",
        "Set publicly_accessible = false and use private subnets with VPN/bastion access.",
        "CWE-284", {"terraform"}, "high"
    ),
    # ── secrets.LEAKED_VALUES ──
    # ── Environment / Logging ──
    (
        "ENV001", "Environment variable leaked in logs",
        r"""(?:console\.log|print|logger?\.(?:info|debug|warn|error)|logging\.)\s*\(.*(?:os\.environ|process\.env)""",
        Severity.MEDIUM, Category.SECRET,
        "Environment variable value written to logs may leak secrets.",
        "Never log raw environment variable values. Mask sensitive values before logging.",
        "CWE-532", None, "low"
    ),
    # ── configuration.REQUEST_HANDLING ──
    # ── Mass Assignment ──
    (
        "API001", "Potential mass assignment",
        r"""(?:\.create|\.update|\.findOneAndUpdate|\.updateOne)\s*\(\s*(?:req\.body|request\.(?:data|json))""",
        Severity.MEDIUM, Category.SECURITY,
        "Directly passing request body to database operations may allow mass assignment.",
        "Explicitly pick allowed fields. Use serializer validation or an allowlist.",
        "CWE-915", {"javascript", "typescript", "python"}, "medium"
    ),
]


# ─── Collect scannable files and evaluate the rule table against their contents.

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
             rules: list = None, file_list: list = None) -> ScanResult:
    """Run a complete scan on a path.

    Args:
        path: Root path for the scan (used for relative path computation).
        min_severity: Minimum severity threshold for reported findings.
        rules: Custom rule set. Defaults to RULES.
        file_list: Optional explicit list of file paths to scan. When
                   provided, only these files are scanned instead of
                   walking the directory tree.
    """
    start_time = time.time()
    result = ScanResult(path=os.path.abspath(path))

    if rules is None:
        rules = RULES

    if file_list is not None:
        # Scan only the explicitly provided files
        files = []
        for fp in file_list:
            abs_fp = os.path.abspath(fp)
            lang = detect_language_from_path(abs_fp)
            if lang and os.path.isfile(abs_fp):
                try:
                    size = os.path.getsize(abs_fp)
                    if size <= MAX_FILE_SIZE:
                        files.append((abs_fp, lang))
                except OSError:
                    pass
    else:
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


# ─── The scanner-local score and grade summarising one set of findings.

TOP_SCORE = 100


DEDUCTION_BY_SEVERITY = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


LINES_PER_SIZE_UNIT = 1000


LENIENCY_PER_SIZE_UNIT = 0.1


GRADE_FLOORS = (
    (95, "A+"),
    (90, "A"),
    (80, "B+"),
    (70, "B"),
    (60, "C"),
    (50, "D"),
)


FAILING_GRADE = "F"


def compute_score(result: ScanResult) -> int:
    """Compute a security score (0-100) from findings."""
    if result.files_scanned == 0:
        return TOP_SCORE

    total_deduction = sum(DEDUCTION_BY_SEVERITY[f.severity] for f in result.findings)

    size_factor = max(1, result.lines_scanned / LINES_PER_SIZE_UNIT)
    adjusted_deduction = total_deduction / (1 + size_factor * LENIENCY_PER_SIZE_UNIT)

    return max(0, min(TOP_SCORE, round(TOP_SCORE - adjusted_deduction)))


def score_to_grade(score: int) -> str:
    """Convert score to letter grade."""
    for floor, grade in GRADE_FLOORS:
        if score >= floor:
            return grade
    return FAILING_GRADE


# ─── Human-readable terminal report, with optional colour.

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
        count = sc[sev]
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


# ─── JSON and SARIF reports for other tools to read.

def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0."""
    return json.dumps(result.to_sarif(), indent=2)


# ─── Markdown report for review threads and job summaries.

SEVERITY_MARKS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


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
        count = sc[sev]
        if count > 0:
            lines.append(f"| {SEVERITY_MARKS[sev]} {sev.upper()} | {count} |")
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
            lines.append(f"- {SEVERITY_MARKS[f.severity.value]} **[{f.rule_id}] {f.title}** (L{f.line_number})")
            lines.append(f"  - {f.description}")
            if show_fix and f.suggestion:
                lines.append(f"  - 💡 **Fix:** {f.suggestion}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"*Generated by [codespy](https://github.com/wisent-ai/codespy) v{__version__}*")

    return "\n".join(lines)


# ─── Command-line arguments, output selection, and the scan exit status.

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
        "--files", nargs="+", metavar="FILE",
        help="Scan only these specific files (instead of walking a directory tree)"
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
    result = run_scan(args.path, min_severity=min_severity,
                      file_list=args.files if args.files else None)

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
