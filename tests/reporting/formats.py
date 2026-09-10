"""Every report format, rendered from a real scan."""

import json

from codespy import format_json, format_markdown, format_sarif, format_terminal, run_scan
from support import assert_eq, assert_gt, assert_in, cleanup, create_temp_project


def test_json_output():
    print("Testing JSON output...")
    tmpdir = create_temp_project({
        "main.py": "password = 'test1234'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_json(result)
        parsed = json.loads(output)
        assert_in("findings", parsed, "JSON has findings key")
        assert_in("severity_counts", parsed, "JSON has severity_counts")
        assert_in("language_stats", parsed, "JSON has language_stats")
        assert_gt(parsed["total_findings"], 0, "JSON reports findings")
    finally:
        cleanup(tmpdir)


def test_sarif_output():
    print("Testing SARIF output...")
    tmpdir = create_temp_project({
        "vuln.py": "password = 'hunter2abc'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_sarif(result)
        parsed = json.loads(output)
        assert_eq(parsed["version"], "2.1.0", "SARIF version 2.1.0")
        assert_in("runs", parsed, "SARIF has runs")
        assert_eq(parsed["runs"][0]["tool"]["driver"]["name"], "codespy", "Tool name is codespy")
        assert_gt(len(parsed["runs"][0]["results"]), 0, "SARIF has results")
    finally:
        cleanup(tmpdir)


def test_markdown_output():
    print("Testing markdown output...")
    tmpdir = create_temp_project({
        "app.py": "password = 'insecure!'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_markdown(result, show_fix=True)
        assert_in("# codespy Security Report", output, "Markdown has title")
        assert_in("Security Score", output, "Markdown has score")
        assert_in("Findings", output, "Markdown has findings section")
        assert_in("Fix:", output, "Markdown shows fixes when requested")
    finally:
        cleanup(tmpdir)


def test_terminal_output():
    print("Testing terminal output...")
    tmpdir = create_temp_project({
        "app.py": "password = 'mysecret1'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_terminal(result, show_fix=True, use_color=False)
        assert_in("codespy", output, "Terminal output has tool name")
        assert_in("Security Score", output, "Terminal output has score")
    finally:
        cleanup(tmpdir)


TESTS = (
    test_json_output,
    test_sarif_output,
    test_markdown_output,
    test_terminal_output,
)
