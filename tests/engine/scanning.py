"""What the scanner opens, what it skips, and how severity filtering narrows it."""

import os

from codespy import RULES, Severity, collect_files, compute_score, detect_language_from_path, run_scan
from support import (
    assert_eq,
    assert_gt,
    assert_gte,
    assert_in,
    assert_true,
    cleanup,
    create_temp_project,
)


def test_language_detection():
    print("Testing language detection...")
    assert_eq(detect_language_from_path("main.py"), "python", "Python detection")
    assert_eq(detect_language_from_path("app.js"), "javascript", "JS detection")
    assert_eq(detect_language_from_path("index.ts"), "typescript", "TS detection")
    assert_eq(detect_language_from_path("main.go"), "go", "Go detection")
    assert_eq(detect_language_from_path("lib.rs"), "rust", "Rust detection")
    assert_eq(detect_language_from_path("App.java"), "java", "Java detection")
    assert_eq(detect_language_from_path("Dockerfile"), "dockerfile", "Dockerfile detection")
    assert_eq(detect_language_from_path("Dockerfile.prod"), "dockerfile", "Dockerfile.prod detection")
    assert_eq(detect_language_from_path("script.sh"), "shell", "Shell detection")
    assert_eq(detect_language_from_path("config.tf"), "terraform", "Terraform detection")
    assert_eq(detect_language_from_path("README.md"), None, "Non-code file returns None")
    assert_eq(detect_language_from_path("image.png"), None, "Image returns None")


def test_file_collection():
    print("Testing file collection...")
    tmpdir = create_temp_project({
        "main.py": "print('hello')",
        "app.js": "console.log('hello')",
        "README.md": "# Hello",
        "src/lib.py": "def foo(): pass",
        "node_modules/pkg/index.js": "module.exports = {}",
        ".git/config": "[core]",
    })

    try:
        files = collect_files(tmpdir)
        paths = [os.path.basename(f[0]) for f in files]

        assert_in("main.py", paths, "Finds Python files")
        assert_in("app.js", paths, "Finds JS files")
        assert_in("lib.py", paths, "Finds nested Python files")
        assert_true("README.md" not in [os.path.basename(f[0]) for f in files],
                    "Skips non-code files")
        assert_true("index.js" not in paths, "Skips node_modules")
        assert_true("config" not in paths, "Skips .git")
    finally:
        cleanup(tmpdir)


def test_severity_filter():
    print("Testing severity filtering...")
    tmpdir = create_temp_project({
        "mixed.py": """
# TODO: fix this
password = "secretpass1"
DEBUG = True
""",
    })

    try:
        # Scan all
        all_result = run_scan(tmpdir, min_severity=Severity.INFO)
        # Scan high+ only
        high_result = run_scan(tmpdir, min_severity=Severity.HIGH)

        assert_gte(all_result.finding_count, high_result.finding_count,
                   "All findings >= high-only findings")
        assert_gt(all_result.finding_count, 0, "Info scan finds issues")

        # Verify high results only have high/critical
        for f in high_result.findings:
            assert_true(f.severity in (Severity.HIGH, Severity.CRITICAL),
                        f"High filter: {f.severity.value} should be high or critical")
    finally:
        cleanup(tmpdir)


def test_single_file_scan():
    print("Testing single file scan...")
    tmpdir = create_temp_project({
        "target.py": "password = 'leaked123'\n",
        "other.py": "api_key = 'sk-abcdefghijk'\n",
    })

    try:
        # Scan just one file
        result = run_scan(os.path.join(tmpdir, "target.py"))
        assert_eq(result.files_scanned, 1, "Only scans one file")

        # Should only find issues in target.py, not other.py
        for f in result.findings:
            assert_true("other.py" not in f.file_path, "Doesn't scan other files")
    finally:
        cleanup(tmpdir)


def test_empty_project():
    print("Testing empty project scan...")
    tmpdir = create_temp_project({})
    try:
        result = run_scan(tmpdir)
        assert_eq(result.files_scanned, 0, "No files scanned")
        assert_eq(result.finding_count, 0, "No findings")
        assert_eq(compute_score(result), 100, "Perfect score for empty project")
    finally:
        cleanup(tmpdir)


def test_rule_count():
    print("Testing rule count...")
    assert_gte(len(RULES), 65, "At least 65 rules defined")


TESTS = (
    test_language_detection,
    test_file_collection,
    test_severity_filter,
    test_single_file_scan,
    test_empty_project,
    test_rule_count,
)
