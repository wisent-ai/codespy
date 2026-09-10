"""Collect scannable files and evaluate the rule table against their contents."""

import os
import re
import time
from collections import Counter
from typing import Optional

from .configuration import LANGUAGE_EXTENSIONS, MAX_FILE_SIZE, SKIP_DIRS
from .models import Category, Finding, ScanResult, Severity
from .rules import RULES


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
