"""The action manifest keys a caller writes in their own workflow."""

from __future__ import annotations

import pathlib

# The two mappings of action.yml whose keys callers write in their own workflows.
ACTION_SECTIONS = ("inputs", "outputs")


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
