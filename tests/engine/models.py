"""Findings, scan results, grades, and the severity words the command accepts."""

from codespy import Category, Finding, ScanResult, Severity, parse_severity, score_to_grade
from support import assert_eq, assert_true


def test_finding_to_dict():
    print("Testing Finding serialization...")
    finding = Finding(
        rule_id="SEC001",
        title="Test finding",
        description="A test",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        file_path="test.py",
        line_number=10,
        line_content="  password = 'test'",
        suggestion="Don't do this",
        cwe_id="CWE-798",
    )
    d = finding.to_dict()
    assert_eq(d["rule_id"], "SEC001", "Dict has rule_id")
    assert_eq(d["severity"], "high", "Severity is string")
    assert_eq(d["cwe_id"], "CWE-798", "Has CWE ID")
    assert_eq(d["line_content"], "password = 'test'", "Line content is stripped")


def test_scan_result_properties():
    print("Testing ScanResult properties...")
    result = ScanResult(path="/test")
    result.findings = [
        Finding("R1", "T1", "D1", Severity.HIGH, Category.SECURITY, "f.py", 1, "", "", ""),
        Finding("R2", "T2", "D2", Severity.HIGH, Category.INJECTION, "f.py", 2, "", "", ""),
        Finding("R3", "T3", "D3", Severity.LOW, Category.QUALITY, "f.py", 3, "", "", ""),
    ]
    assert_eq(result.finding_count, 3, "Finding count")
    assert_eq(result.severity_counts["high"], 2, "High severity count")
    assert_eq(result.severity_counts["low"], 1, "Low severity count")
    assert_eq(result.severity_counts["critical"], 0, "A severity with no findings is counted as zero, not left out")
    assert_eq(sorted(result.severity_counts), ["critical", "high", "info", "low", "medium"], "Every severity is present")
    assert_eq(result.category_counts.get("security"), 1, "Security category count")


def test_scoring():
    print("Testing scoring system...")
    assert_eq(score_to_grade(100), "A+", "Perfect score = A+")
    assert_eq(score_to_grade(95), "A+", "95 = A+")
    assert_eq(score_to_grade(90), "A", "90 = A")
    assert_eq(score_to_grade(80), "B+", "80 = B+")
    assert_eq(score_to_grade(70), "B", "70 = B")
    assert_eq(score_to_grade(60), "C", "60 = C")
    assert_eq(score_to_grade(50), "D", "50 = D")
    assert_eq(score_to_grade(30), "F", "30 = F")


def test_severity_parsing():
    print("Testing severity parsing...")
    assert_eq(parse_severity("info"), Severity.INFO, "Parse info")
    assert_eq(parse_severity("critical"), Severity.CRITICAL, "Parse critical")
    assert_eq(parse_severity("HIGH"), Severity.HIGH, "Parse HIGH (case insensitive)")

    try:
        parse_severity("invalid")
        assert_true(False, "Should raise ValueError for invalid severity")
    except ValueError:
        assert_true(True, "Raises ValueError for invalid severity")


TESTS = (
    test_finding_to_dict,
    test_scan_result_properties,
    test_scoring,
    test_severity_parsing,
)
