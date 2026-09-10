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
    python3 tests/surface.py [root]     # root defaults to the repository
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys

from release.manifest import ACTION_SECTIONS, manifest_keys
from release.rules import (
    CATEGORY_ENUM,
    SEVERITY_ENUM,
    cli_vocabulary,
    rule_entries,
    rule_ids,
    scanned_paths,
    used_categories,
)
from release.reading import enum_values, parse

MODULE = "codespy.py"
ACTION = "action.yml"



INDENT = int(True) + int(True)












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
