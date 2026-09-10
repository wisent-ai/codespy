"""Read a released module with `ast`, never by importing it.

Importing would execute the scanner and require a Python that can run it; a release
decision must not depend on either. Reading also works against an unpacked sdist.
"""

from __future__ import annotations

import ast
import pathlib


def parse(source: pathlib.Path) -> ast.Module:
    """The module's syntax tree, or a loud failure."""
    try:
        return ast.parse(source.read_text(), filename=str(source))
    except OSError as error:
        raise SystemExit(f"{source}: {error}") from error
    except SyntaxError as error:
        # Refuse rather than degrade. A module that does not parse cannot run either,
        # so its rules are unreachable — but reporting the smaller surface would read
        # to the versioning rule as a deliberate removal of capability. The surface is
        # unknown here, not shrunk, and only a human can tell those apart.
        raise SystemExit(
            f"{source}: does not parse, so the surface is unknown: {error}"
        ) from error


def module_constants(tree: ast.Module) -> dict:
    """Module-level `NAME = value` and `NAME: T = value`, as unevaluated nodes."""
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
        else:
            continue
        for target in targets:
            found[target.id] = node.value
    return found


def require(mapping: dict, name: str, kind: type, source: pathlib.Path) -> ast.expr:
    """A module-level constant of the expected shape, or a loud failure."""
    node = mapping.get(name)
    if node is None:
        raise SystemExit(
            f"{source}: no module-level {name}. It was renamed or moved, which changes "
            "what this tool promises, so refusing rather than guessing"
        )
    if not isinstance(node, kind):
        raise SystemExit(
            f"{source}: {name} is no longer a literal {kind.__name__.lower()}, so its "
            "contents cannot be read without running the module"
        )
    return node


def literal_strings(nodes: list) -> list:
    """Only the string literals, ignoring None and computed entries."""
    return [n.value for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def enum_values(tree: ast.Module, name: str, source: pathlib.Path) -> dict:
    """`MEMBER = "value"` pairs of a str-valued Enum class."""
    values = {}
    for node in tree.body:
        if not (isinstance(node, ast.ClassDef) and node.name == name):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign):
                continue
            if not (isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)):
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = statement.value.value
    if not values:
        raise SystemExit(
            f"{source}: class {name} has no string members. Its vocabulary appears in "
            "every report this tool writes, so refusing rather than reporting none"
        )
    return values
