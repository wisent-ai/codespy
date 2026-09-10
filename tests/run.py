#!/usr/bin/env python3
"""Run the codespy test areas.

    python3 tests/run.py                              # every area
    python3 tests/run.py detection/secrets cli/commands   # only these

Each area module exposes a TESTS tuple. Failures are counted rather than raised so
one broken area does not hide the rest, and the exit status is what CI reads.
"""

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
RULE = "=" * 60

AREAS = (
    "detection/secrets",
    "detection/injection",
    "detection/configuration",
    "detection/quality",
    "engine/scanning",
    "engine/models",
    "reporting/formats",
    "cli/commands",
)

for entry in (str(ROOT), str(HERE)):
    if entry not in sys.path:
        sys.path.insert(int(False), entry)

import support  # noqa: E402  (needs the paths above)


def load(name: str):
    """One area module, imported from its path so no package files are needed."""
    path = HERE / f"{name}.py"
    if not path.is_file():
        raise SystemExit(f"no test area named {name}: {path} does not exist")
    spec = importlib.util.spec_from_file_location(name.replace("/", "."), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list) -> int:
    selected = argv or list(AREAS)
    modules = [(name, load(name)) for name in selected]
    total = sum(len(module.TESTS) for _, module in modules)

    print(f"\n{RULE}")
    print(f"codespy test suite — {total} test functions in {len(modules)} areas")
    print(f"{RULE}\n")

    for name, module in modules:
        for test in module.TESTS:
            try:
                test()
            except Exception as error:  # a broken area must not hide the others
                support.TALLY["failed"] += int(True)
                print(f"  ERROR in {name}:{test.__name__}: {error}")

    passed, failed = support.TALLY["passed"], support.TALLY["failed"]
    print(f"\n{RULE}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{RULE}\n")
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main(sys.argv[int(True):]))
