"""The shipped command itself: what it prints, what it writes, and how it exits.

Everything here runs `python3 codespy.py` as a separate process, because that is
what a person and a CI job run. The in-process areas cover the rules; this covers
the contract around them: exit statuses, written report files, and refusals.
"""

import json
import pathlib
import subprocess
import sys

from support import ROOT, assert_eq, assert_gt, assert_in, assert_true, cleanup, create_temp_project

SCANNER = ROOT / "codespy.py"
CLEAN = "def add(a: int, b: int) -> int:\n    return a + b\n"
LEAKED = 'password = "supersecret123"\n'
NO_FINDINGS = int(False)
FINDINGS_PRESENT = int(True)
USAGE_ERROR = int(True)


def scan(*arguments):
    """Run the released scanner and return its completed process."""
    return subprocess.run(
        [sys.executable, str(SCANNER), *arguments],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_version_is_printed_and_exits_cleanly():
    print("Testing codespy --version...")
    result = scan("--version")
    assert_eq(result.returncode, NO_FINDINGS, "--version exits zero")
    assert_in("codespy ", result.stdout, "--version names the tool and its version")


def test_clean_project_reports_nothing_and_exits_zero():
    print("Testing a clean project through the command...")
    project = create_temp_project({"clean.py": CLEAN})
    try:
        result = scan(project, "--no-color")
        assert_eq(result.returncode, NO_FINDINGS, "A clean project exits zero")
        assert_in("No issues found.", result.stdout, "A clean project says so")
    finally:
        cleanup(project)


def test_critical_finding_exits_one_and_shows_the_fix():
    print("Testing a critical finding through the command...")
    project = create_temp_project({"config.py": LEAKED})
    try:
        result = scan(project, "--no-color", "--fix")
        assert_eq(result.returncode, FINDINGS_PRESENT, "A critical finding exits one")
        assert_in("SEC001", result.stdout, "The report names the rule")
        assert_in("secrets manager", result.stdout, "--fix prints the suggestion")
    finally:
        cleanup(project)


def test_json_report_is_written_to_the_requested_file():
    print("Testing --format json --output...")
    project = create_temp_project({"config.py": LEAKED})
    report = pathlib.Path(project) / "report.json"
    try:
        result = scan(project, "--format", "json", "--output", str(report))
        assert_eq(result.returncode, FINDINGS_PRESENT, "Findings still set the exit status")
        assert_in(str(report), result.stdout, "The command says where it wrote the report")
        document = json.loads(report.read_text(encoding="utf-8"))
        assert_gt(document["total_findings"], NO_FINDINGS, "The report carries findings")
        assert_in("SEC001", [f["rule_id"] for f in document["findings"]], "SEC001 is reported")
        assert_gt(document["severity_counts"]["critical"], NO_FINDINGS, "Counted as critical")
    finally:
        cleanup(project)


def test_sarif_report_is_written_for_code_scanning():
    print("Testing --format sarif --output...")
    project = create_temp_project({"config.py": LEAKED})
    report = pathlib.Path(project) / "report.sarif"
    try:
        scan(project, "--format", "sarif", "--output", str(report))
        document = json.loads(report.read_text(encoding="utf-8"))
        assert_eq(document["version"], "2.1.0", "SARIF 2.1.0 is written")
        run = document["runs"][NO_FINDINGS]
        assert_eq(run["tool"]["driver"]["name"], "codespy", "The driver names codespy")
        assert_gt(len(run["results"]), NO_FINDINGS, "SARIF carries results")
    finally:
        cleanup(project)


def test_severity_filter_hides_lower_findings():
    print("Testing --severity through the command...")
    project = create_temp_project({"main.py": "# TODO: fix this later\n"})
    try:
        every = scan(project, "--no-color")
        high = scan(project, "--no-color", "--severity", "high")
        assert_in("QUA001", every.stdout, "An info finding is reported by default")
        assert_true("QUA001" not in high.stdout, "--severity high hides an info finding")
        assert_eq(high.returncode, NO_FINDINGS, "Nothing high or critical exits zero")
    finally:
        cleanup(project)


def test_unknown_severity_is_refused():
    print("Testing an unknown severity...")
    result = scan(".", "--severity", "unsupported")
    assert_eq(result.returncode, USAGE_ERROR, "An unknown severity exits non-zero")
    assert_eq(
        result.stderr.strip(),
        "Error: Invalid severity: unsupported. Choose from: info, low, medium, high, critical",
        "The refusal names the accepted words",
    )


def test_missing_path_is_refused():
    print("Testing a path that does not exist...")
    missing = str(ROOT / "build" / "no-such-project")
    result = scan(missing)
    assert_eq(result.returncode, USAGE_ERROR, "A missing path exits non-zero")
    assert_eq(
        result.stderr.strip(),
        f"Error: Path '{missing}' does not exist.",
        "The refusal names the path",
    )


TESTS = (
    test_version_is_printed_and_exits_cleanly,
    test_clean_project_reports_nothing_and_exits_zero,
    test_critical_finding_exits_one_and_shows_the_fix,
    test_json_report_is_written_to_the_requested_file,
    test_sarif_report_is_written_for_code_scanning,
    test_severity_filter_hides_lower_findings,
    test_unknown_severity_is_refused,
    test_missing_path_is_refused,
)
