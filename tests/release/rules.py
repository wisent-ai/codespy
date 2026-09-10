"""What the rule table, the language manifest and the command line promise."""

from __future__ import annotations

import ast
import pathlib

from .reading import enum_values, literal_strings, module_constants, require

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
