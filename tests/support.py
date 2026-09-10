"""Assertions and disposable projects shared by every codespy test area.

A test project is created inside this checkout's ignored build directory rather
than the machine's temporary directory, so a run leaves nothing outside the
repository and a failed run leaves its fixture where it can still be read.
"""

import pathlib
import shutil
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = ROOT / "build" / "test-projects"

if str(ROOT) not in sys.path:
    sys.path.insert(int(False), str(ROOT))

TALLY = {"passed": int(False), "failed": int(False)}


def assert_true(condition, msg=""):
    if condition:
        TALLY["passed"] += int(True)
    else:
        TALLY["failed"] += int(True)
        print(f"  FAIL: {msg}")


def assert_eq(a, b, msg=""):
    assert_true(a == b, f"{msg} — expected {b!r}, got {a!r}")


def assert_in(item, container, msg=""):
    assert_true(item in container, f"{msg} — {item!r} not in result")


def assert_gte(a, b, msg=""):
    assert_true(a >= b, f"{msg} — {a} < {b}")


def assert_gt(a, b, msg=""):
    assert_true(a > b, f"{msg} — {a} <= {b}")


def create_temp_project(files: dict) -> str:
    """A disposable project holding these files. Returns its path."""
    FIXTURES.mkdir(parents=True, exist_ok=True)
    directory = tempfile.mkdtemp(prefix="codespy_test_", dir=FIXTURES)
    for name, content in files.items():
        path = pathlib.Path(directory) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return directory


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)
