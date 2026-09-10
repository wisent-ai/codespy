"""Maintainability rules, and the score a project without findings earns."""

from codespy import compute_score, run_scan
from support import assert_eq, assert_gte, assert_in, cleanup, create_temp_project


def test_todo_detection():
    print("Testing TODO/FIXME detection...")
    tmpdir = create_temp_project({
        "main.py": """
# TODO: fix this later
# FIXME: urgent bug
def broken(): pass
""",
    })

    try:
        result = run_scan(tmpdir)
        todo_findings = [f for f in result.findings if f.rule_id == "QUA001"]
        assert_gte(len(todo_findings), 2, "Detects TODO and FIXME")
    finally:
        cleanup(tmpdir)


def test_mutable_default():
    print("Testing mutable default argument detection...")
    tmpdir = create_temp_project({
        "func.py": """
def process(items=[]):
    items.append(1)
    return items
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("QUA003", rule_ids, "Detects mutable default argument")
    finally:
        cleanup(tmpdir)


def test_console_log():
    print("Testing console.log detection in JS...")
    tmpdir = create_temp_project({
        "debug.js": """
function handler(req) {
    console.log("debug:", req.body);
    return process(req);
}
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("QUA005", rule_ids, "Detects console.log")
    finally:
        cleanup(tmpdir)


def test_clean_code():
    print("Testing clean code gets high score...")
    tmpdir = create_temp_project({
        "clean.py": """
def add(a: int, b: int) -> int:
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"
""",
    })

    try:
        result = run_scan(tmpdir)
        score = compute_score(result)
        assert_gte(score, 90, f"Clean code scores high: {score}")
        assert_eq(len(result.findings), 0, "No findings for clean code")
    finally:
        cleanup(tmpdir)


TESTS = (
    test_todo_detection,
    test_mutable_default,
    test_console_log,
    test_clean_code,
)
