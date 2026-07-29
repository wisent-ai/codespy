"""Print this tool's public surface: what a codespy user would notice disappearing.

codespy is a single-file scanner published as a GitHub Action, not a library. It has no
`__all__` and nobody imports it, so its Python symbols are not the contract — its
*observable behaviour* is. Nine things are observable, and each one is something a
caller has written down somewhere outside this repository:

    rule:SEC001       the identifier in JSON `rule_id` and SARIF `ruleId`. Suppression
                      lists, baseline files and dashboards key on these strings. A
                      retired rule id silently stops failing a build that relied on it.
    category:secret   a value of the `category` field and a key of `category_counts`.
                      Emitted only when some rule actually uses it, because that is
                      exactly when a consumer can see it.
    severity:critical accepted by `--severity` *and* emitted, and it decides the exit
                      code: critical and high mean non-zero. Both directions break.
    language:python   a key of `language_stats`.
    ext:.cjs          an entry of the `LANGUAGE_EXTENSIONS` manifest — the suffixes
                      that get opened at all. This is the one group that is invisible
                      in every other list: drop `.cjs` and the scanner reports a clean
                      tree because it never read the file. Silent blindness is the
                      worst break a scanner can ship, so the suffixes are named
                      individually rather than folded into their language.
    format:sarif      a `--format` choice. Removing one breaks whoever pipes it.
    cli:--no-color    every option string and positional of the CLI, which is the
                      whole command vocabulary a script can invoke.
    action-input:severity     a declared input of action.yml. This is the primary
                      distribution channel: there is no package on any index, and every
                      README example is `uses: wisent-ai/codespy@v1`, so what callers
                      actually write is a `with:` block. The input names differ from the
                      CLI spellings they forward to — `output-file` against `--output`,
                      `fail-on-findings` against no flag at all — so the CLI list does
                      not cover them and cannot.
    action-output:security-score
                      a declared output of action.yml, named in a caller's
                      `steps.<id>.outputs.<name>`. Deleting one silently yields the
                      empty string in someone else's workflow expression rather than
                      failing, which is the quietest break in this whole list.

Not included: the regexes, the fix suggestions, the CWE ids and the per-rule language
scoping. Those change what a rule *finds*, and a scanner is expected to get better at
finding things — the rule id is the promise, its pattern is an implementation.

Also not included, and a known gap rather than a decision: `detect_language_from_path`
recognises `Dockerfile*`, `Makefile`, `makefile` and `GNUmakefile` in control flow
instead of in the manifest, so deleting those branches would go unnoticed here. Moving
them into `LANGUAGE_EXTENSIONS` would close the gap. Relatedly, the manifest's
`"dockerfile": {"Dockerfile"}` entry is already dead — the lookup it feeds compares
against `os.path.splitext` suffixes, which never equal a bare filename — so `ext:`
reports what the manifest declares, not what the branch above it happens to catch.

Read with `ast`, never by importing. codespy is advertised as zero-dependency, but
importing it still executes the module and requires a Python that can run it; a release
decision must not depend on either. Reading also means this script runs unchanged
against an unpacked sdist, so the surface of an already published version can be
recovered exactly rather than assumed.

Usage:
    python3 scripts/surface.py [root]     # root defaults to the repository
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys

MODULE = "codespy.py"
ACTION = "action.yml"

# The two mappings of action.yml whose keys callers write in their own workflows.
ACTION_SECTIONS = ("inputs", "outputs")

# The layout of a RULES entry, from the comment above the table. Field names stand in
# for positions so that this file carries no bare offsets to drift out of date.
RULE_FIELDS = (
    "rule_id",
    "title",
    "pattern",
    "severity",
    "category",
    "description",
    "suggestion",
    "cwe_id",
    "languages",
    "confidence",
)

RULES_TABLE = "RULES"
EXTENSION_MAP = "LANGUAGE_EXTENSIONS"
SEVERITY_ENUM = "Severity"
CATEGORY_ENUM = "Category"
FORMAT_OPTION = "--format"
ADD_ARGUMENT = "add_argument"

INDENT = int(True) + int(True)


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


def rule_entries(tree: ast.Module, source: pathlib.Path) -> list:
    """The literal tuples of the RULES table."""
    table = require(module_constants(tree), RULES_TABLE, ast.List, source)
    entries = [e for e in table.elts if isinstance(e, ast.Tuple)]
    if len(entries) != len(table.elts):
        raise SystemExit(
            f"{source}: {RULES_TABLE} holds entries that are not literal tuples, so "
            "some rule ids cannot be read without running the module"
        )
    return entries


def field_of(entry: ast.Tuple, field: str) -> ast.expr:
    """One positional field of a rule tuple, by the name it has in RULE_FIELDS."""
    return entry.elts[RULE_FIELDS.index(field)]


def rule_ids(entries: list, source: pathlib.Path) -> list:
    """The identifier every finding and every SARIF result is stamped with."""
    ids = []
    for entry in entries:
        if len(entry.elts) != len(RULE_FIELDS):
            raise SystemExit(
                f"{source}: a {RULES_TABLE} entry has {len(entry.elts)} fields, not "
                f"{len(RULE_FIELDS)}. The tuple layout changed, so reading it by "
                "position would report the wrong rule ids"
            )
        name = field_of(entry, "rule_id")
        if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
            raise SystemExit(
                f"{source}: a {RULES_TABLE} entry has a computed rule id, which cannot "
                "be read without running the module"
            )
        ids.append(name.value)
    duplicates = sorted({i for i in ids if ids.count(i) > len(("once",))})
    if duplicates:
        raise SystemExit(
            f"{source}: duplicate rule ids {', '.join(duplicates)}. Two rules reporting "
            "the same id make suppressions ambiguous"
        )
    return ids


def used_categories(entries: list, categories: dict, source: pathlib.Path) -> list:
    """Category values that some rule can actually emit."""
    used = set()
    for entry in entries:
        node = field_of(entry, "category")
        if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)):
            continue
        if node.value.id != CATEGORY_ENUM:
            continue
        if node.attr not in categories:
            raise SystemExit(
                f"{source}: a rule names {CATEGORY_ENUM}.{node.attr}, which the enum "
                "does not define"
            )
        used.add(categories[node.attr])
    if not used:
        raise SystemExit(
            f"{source}: no rule names a {CATEGORY_ENUM} member, so the category field "
            "of every report is unreadable from the source"
        )
    return sorted(used)


def scanned_paths(tree: ast.Module, source: pathlib.Path) -> tuple:
    """Language names and the filename suffixes each one claims."""
    mapping = require(module_constants(tree), EXTENSION_MAP, ast.Dict, source)
    languages = literal_strings(list(mapping.keys))
    suffixes = set()
    for value in mapping.values:
        if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
            suffixes.update(literal_strings(list(value.elts)))
    if not languages or not suffixes:
        raise SystemExit(
            f"{source}: {EXTENSION_MAP} yielded no languages or no suffixes, which "
            "would mean this tool scans nothing"
        )
    return languages, sorted(suffixes)


def cli_vocabulary(tree: ast.Module, source: pathlib.Path) -> tuple:
    """Every CLI name, and the choices offered for the output format."""
    names = set()
    formats = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == ADD_ARGUMENT):
            continue
        spellings = literal_strings(list(node.args))
        names.update(spellings)
        if FORMAT_OPTION not in spellings:
            continue
        for keyword in node.keywords:
            if keyword.arg == "choices" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                formats.update(literal_strings(list(keyword.value.elts)))
    if not names:
        raise SystemExit(
            f"{source}: found no {ADD_ARGUMENT} calls, so the command line this tool "
            "offers is unreadable from the source"
        )
    if not formats:
        raise SystemExit(
            f"{source}: {FORMAT_OPTION} offers no literal choices, so the set of output "
            "formats is unreadable from the source"
        )
    return sorted(names), sorted(formats)


def manifest_keys(manifest: pathlib.Path, section: str) -> list:
    """Immediate keys of one top-level mapping of action.yml.

    Deliberately not a YAML parser and deliberately not PyYAML. The surface must be
    readable with nothing installed — a release decision that needs a dependency is a
    release decision that stops working on some machine — and the two sections this
    cares about are flat mappings of plain names. So the shape is asserted instead of
    interpreted: a top-level `section:`, then its immediate children, one indent deeper,
    each a bare `name:`. Anything else raises, because a silently short list of input
    names would read to the versioning rule as inputs a caller can no longer pass.
    """
    try:
        lines = manifest.read_text().splitlines()
    except OSError as error:
        raise SystemExit(f"{manifest}: {error}") from error

    opener = f"{section}:"
    starts = [index for index, line in enumerate(lines) if line == opener]
    if not starts:
        raise SystemExit(
            f"{manifest}: no top-level `{opener}`. This manifest is how callers address "
            f"the action, so refusing rather than reporting no {section}"
        )
    if len(starts) > len(("once",)):
        raise SystemExit(f"{manifest}: `{opener}` appears more than once")

    body = lines[starts.pop() + int(True) :]
    depth = None
    keys = []
    for line in body:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == int(False):
            break
        if "\t" in line[:indent]:
            raise SystemExit(f"{manifest}: tab indentation in `{section}`, refusing to guess")
        if depth is None:
            depth = indent
        if indent != depth:
            continue
        name, separator, _ = line.strip().partition(":")
        if not separator:
            raise SystemExit(
                f"{manifest}: `{line.strip()}` under `{section}` is not a `name:` entry, "
                "so the manifest is not the flat mapping this reader asserts"
            )
        keys.append(name.strip().strip("'\""))
    if not keys:
        raise SystemExit(f"{manifest}: `{opener}` is empty")
    return keys


def surface(root: pathlib.Path) -> list:
    """Everything a caller of this tool can observe, namespaced and sorted."""
    source = root / MODULE
    if not source.is_file():
        raise SystemExit(f"{source} does not exist; is {root} the repository root?")
    tree = parse(source)

    entries = rule_entries(tree, source)
    categories = enum_values(tree, CATEGORY_ENUM, source)
    severities = enum_values(tree, SEVERITY_ENUM, source)
    languages, suffixes = scanned_paths(tree, source)
    cli, formats = cli_vocabulary(tree, source)

    manifest = root / ACTION
    if not manifest.is_file():
        raise SystemExit(
            f"{manifest} does not exist. The action manifest is how callers address this "
            "tool, so its inputs and outputs are part of the contract; without it the "
            "surface would be short by every name a `with:` block writes, and the "
            "versioning rule would read that as removed capability"
        )
    inputs, outputs = (manifest_keys(manifest, section) for section in ACTION_SECTIONS)

    groups = {
        "rule": rule_ids(entries, source),
        "category": used_categories(entries, categories, source),
        "severity": sorted(severities.values()),
        "language": languages,
        "ext": suffixes,
        "format": formats,
        "cli": cli,
        "action-input": inputs,
        "action-output": outputs,
    }
    return sorted({f"{prefix}:{name}" for prefix, names in groups.items() for name in names})


def main(argv: list) -> int:
    positional = [arg for arg in argv if not arg.startswith("-")]
    root = (
        pathlib.Path(positional[int(False)])
        if positional
        else pathlib.Path(__file__).resolve().parent.parent
    )
    print(json.dumps({"surface": surface(root)}, indent=INDENT))
    return int(False)


if __name__ == "__main__":
    sys.exit(main(sys.argv[int(True):]))
