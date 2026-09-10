#!/usr/bin/env python3
"""Render the released standalone codespy.py from the codespy_core package.

codespy ships as one file a person can download and read, with no runtime package
to install. That file is also too large to maintain by hand, so the source lives in
codespy_core/ and this program renders the release from it.

    python3 tools/build_codespy.py            # rewrite codespy.py from the package
    python3 tools/build_codespy.py --check    # fail when codespy.py is stale

What it guarantees:

- the rule table stays one literal list, in the order codespy_core/rules declares,
  because tests/surface.py reads the released contract without running the module;
- imports are the ones the modules actually use, sorted and deduplicated;
- the same package always renders the same bytes, so --check is meaningful in CI.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(int(False), str(ROOT))

from codespy_core.rules import FAMILY_ORDER  # noqa: E402  (needs ROOT on sys.path)

PACKAGE = ROOT / "codespy_core"
TARGET = ROOT / "codespy.py"
RULES_TABLE = "RULES"
FIRST = int(True)

# Definition order of the rendered file. A name must exist before the line that reads
# it at import time, which is why the constants, models and rules come first.
MODULES = (
    "configuration.py",
    "models.py",
    "scanner.py",
    "reporting/scoring.py",
    "reporting/terminal.py",
    "reporting/structured.py",
    "reporting/markdown.py",
    "cli.py",
)

# The rule table is rendered after this module and before the scanner that reads it.
RULES_AFTER = "models.py"

HEADER = '''#!/usr/bin/env python3
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
'''

FOOTER = '''if __name__ == "__main__":
    main()
'''


def parsed(path: pathlib.Path) -> tuple:
    """The module's syntax tree and its source lines."""
    source = path.read_text(encoding="utf-8")
    try:
        return ast.parse(source, filename=str(path)), source.splitlines()
    except SyntaxError as error:
        raise SystemExit(f"{path}: cannot be rendered because it does not parse: {error}")


def is_docstring(node: ast.stmt, index: int) -> bool:
    """Whether this statement is the module docstring."""
    return (
        index == int(False)
        and isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def span(lines: list, node: ast.stmt) -> str:
    """The exact source of one statement, decorators and inline comments included."""
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return "\n".join(lines[start - FIRST : node.end_lineno])


def imports_and_body(path: pathlib.Path) -> tuple:
    """Absolute imports the module needs, and every other top-level statement."""
    tree, lines = parsed(path)
    plain, grouped, body = set(), {}, []
    for index, node in enumerate(tree.body):
        if is_docstring(node, index):
            continue
        if isinstance(node, ast.Import):
            plain.update(
                alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"
                for alias in node.names
            )
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level or node.module == "__future__":
                continue  # a sibling module the rendered file inlines instead
            grouped.setdefault(node.module, set()).update(a.name for a in node.names)
            continue
        body.append(span(lines, node))
    return (plain, grouped), body


def render_imports(plain: set, grouped: dict) -> str:
    """One import block for the whole rendered file."""
    lines = [f"import {name}" for name in sorted(plain)]
    lines.extend(
        f"from {module} import {', '.join(sorted(names))}"
        for module, names in sorted(grouped.items())
    )
    return "\n".join(lines)


def family_source(module_name: str, family_name: str) -> str:
    """The entries of one rule family, exactly as written, comments included."""
    path = PACKAGE / "rules" / f"{module_name}.py"
    tree, lines = parsed(path)
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.List):
            continue
        if not any(isinstance(t, ast.Name) and t.id == family_name for t in node.targets):
            continue
        return "\n".join(lines[node.value.lineno : node.value.end_lineno - FIRST])
    raise SystemExit(
        f"{path}: no rule family named {family_name}, which rules/__init__.py declares"
    )


def render_rules() -> str:
    """The whole detection table as one list literal, in declared order."""
    table = [f"{RULES_TABLE} = ["]
    for module_name, family_name in FAMILY_ORDER:
        table.append(f"    # ── {module_name}.{family_name} ──")
        table.append(family_source(module_name, family_name))
    table.append("]")
    return "\n".join(table)


def heading_of(path: pathlib.Path, relative: str) -> str:
    """The module's own first docstring line, used as the section banner."""
    tree = parsed(path)[int(False)]
    first = tree.body[int(False)] if tree.body else None
    if first is not None and is_docstring(first, int(False)):
        return first.value.value.splitlines()[int(False)]
    return relative


def render() -> str:
    """The complete standalone file."""
    plain, grouped, sections = set(), {}, []
    for relative in MODULES:
        path = PACKAGE / relative
        (module_plain, module_grouped), body = imports_and_body(path)
        plain.update(module_plain)
        for module, names in module_grouped.items():
            grouped.setdefault(module, set()).update(names)
        sections.append(f"# ─── {heading_of(path, relative)}\n\n" + "\n\n\n".join(body))
        if relative == RULES_AFTER:
            sections.append(
                "# ─── Detection rules, in the order codespy_core/rules declares.\n\n"
                + render_rules()
            )
    parts = [HEADER, render_imports(plain, grouped), "\n\n\n".join(sections), FOOTER]
    return "\n\n\n".join(part.strip("\n") for part in parts) + "\n"


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description="Render codespy.py from codespy_core.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when codespy.py differs from what the package renders",
    )
    arguments = parser.parse_args(argv)

    rendered = render()
    try:
        ast.parse(rendered, filename=str(TARGET))
    except SyntaxError as error:
        raise SystemExit(f"{TARGET}: the rendered file does not parse: {error}")

    if arguments.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current == rendered:
            print(f"{TARGET.name} matches codespy_core")
            return int(False)
        print(f"{TARGET.name} is stale: run python3 tools/build_codespy.py", file=sys.stderr)
        return FIRST

    TARGET.write_text(rendered, encoding="utf-8")
    print(f"wrote {TARGET.name} ({len(rendered.splitlines())} lines) from codespy_core")
    return int(False)


if __name__ == "__main__":
    sys.exit(main(sys.argv[FIRST:]))
