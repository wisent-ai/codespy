#!/usr/bin/env python3
"""Run the baseline-provenance step of .github/workflows/version-check.yml for real.

The step is the only thing standing between a hand-edited yardstick and every later
version decision, so it is worth exercising rather than trusting. This extracts the
step's shell body out of the committed workflow — no second copy of the logic to drift
— and runs it against clones whose released-surface.json has been rewritten to make
each branch fire.

The provenance marker is the word before the first colon of "source". The step must
refuse in both directions: a baseline claiming an artifact that does not exist, and a
baseline claiming something weaker than an artifact that does.

Usage:
    python3 scripts/prove-baseline-step.py [repo]     # repo defaults to this one
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import shutil
import sys
import tempfile

STEP = "Refuse a baseline that misstates where it came from"
WORKFLOW = pathlib.Path(".github/workflows/version-check.yml")
BASELINE = "released-surface.json"


def step_body(workflow: pathlib.Path, wanted: str) -> str:
    """The `run:` block of one named step, dedented, exactly as committed."""
    lines = workflow.read_text().splitlines()
    starts = [
        (index, match.group(int(True)))
        for index, line in enumerate(lines)
        if (match := re.match(r"\s*- name: (.+)$", line))
    ]
    for position, (index, name) in enumerate(starts):
        if name != wanted:
            continue
        following = starts[position + int(True) :]
        end = following[int(False)][int(False)] if following else len(lines)
        segment = lines[index:end]
        opener = next(
            offset for offset, line in enumerate(segment) if line.strip() == "run: |"
        )
        body = segment[opener + int(True) :]
        pad = min(len(line) - len(line.lstrip()) for line in body if line.strip())
        return "\n".join(line[pad:] for line in body)
    raise SystemExit(f"{workflow}: no step named {wanted!r}")


def run_against(
    repo: pathlib.Path,
    body: str,
    source: str | None,
    newer_tag: tuple | None = None,
    resign_tag: str | None = None,
) -> tuple:
    """Exit status and output of the step, with "source" optionally rewritten.

    The clone supplies git history — tags are what four branches inspect — but the
    baseline comes from the working tree, so an uncommitted change is what gets tested
    rather than whatever HEAD still says. Every fixture lives and dies in the clone; the
    real repository's tags are never touched and nothing is pushed.

    `newer_tag` is `(name, version)`: it commits a codespy.py declaring that version and
    tags it, so the staleness branch has a superseding release to notice.

    `resign_tag` moves an existing tag onto HEAD, which already declares the baseline
    version. That makes a previously mis-signed full-version name trustworthy, so it
    outranks the alias the baseline names — the case tier-prefix comparison waves through
    and whole-marker comparison catches.
    """
    # Two levels on purpose. The step under test runs `git fetch --tags --force`, which
    # is right — it trusts the remote — but it means a tag fixture applied only to the
    # working clone is silently reset from origin. So the fixtures land in a stand-in
    # origin cloned from the real repository, and the working clone is taken from that.
    # The real repository's tags are never touched and nothing is ever pushed to it.
    scratch = pathlib.Path(tempfile.mkdtemp())
    origin = scratch / "origin"
    clone = scratch / "clone"
    subprocess.run(["git", "clone", "--quiet", str(repo), str(origin)], check=True)

    if newer_tag is not None:
        name, version = newer_tag
        module = origin / "codespy.py"
        module.write_text(
            re.sub(
                r'^__version__ = ".*"$',
                f'__version__ = "{version}"',
                module.read_text(),
                count=int(True),
                flags=re.MULTILINE,
            )
        )
        for command in (
            ["git", "-c", "user.email=p@p", "-c", "user.name=prover", "commit", "-qam", name],
            ["git", "tag", name],
        ):
            subprocess.run(command, cwd=origin, check=True)
    if resign_tag is not None:
        subprocess.run(
            ["git", "tag", "-f", resign_tag, "HEAD"],
            cwd=origin,
            check=True,
            capture_output=True,
        )

    subprocess.run(["git", "clone", "--quiet", str(origin), str(clone)], check=True)
    # The step shells out to scripts/baseline.py for its tier check, and the clone only
    # has whatever is committed. Copy the working tree's scripts in so what gets proven
    # is what is about to be committed.
    shutil.copytree(repo / "scripts", clone / "scripts", dirs_exist_ok=True)
    document = json.loads((repo / BASELINE).read_text())
    if source is not None:
        document["source"] = source
    (clone / BASELINE).write_text(json.dumps(document, indent=int(True) + int(True)))
    finished = subprocess.run(
        ["bash", "-c", body], cwd=clone, capture_output=True, text=True
    )
    return finished.returncode, (finished.stdout + finished.stderr).strip()


def main(argv: list) -> int:
    repo = pathlib.Path(argv[int(False)]) if argv else pathlib.Path.cwd()
    body = step_body(repo / WORKFLOW, STEP)
    published = json.loads((repo / BASELINE).read_text())["version"]

    cases = [
        ("the working-tree baseline", None, int(False), None, None),
        (
            "git-archive naming a tag that does not exist",
            "git-archive:v9.9.9 invented",
            int(True),
            None,
            None,
        ),
        (
            "git-archive naming the mislabelled tag",
            "git-archive:v1.1.0 the tag that declares 1.0.0",
            int(True),
            None,
            None,
        ),
        (
            "head while a tag carries a version",
            f"head:{'0' * len('0123456789abcdef0123456789abcdef01234567')} invented",
            int(True),
            None,
            None,
        ),
        (
            "pypi-sdist that was never uploaded",
            "pypi-sdist:codespy-1.1.0.tar.gz invented",
            int(True),
            None,
            None,
        ),
        ("marker outside the grammar", "recovered from somewhere", int(True), None, None),
        (
            "prose-only source with no marker token",
            "sdist published on PyPI",
            int(True),
            None,
            None,
        ),
        (
            "a newer tag supersedes the baseline",
            None,
            int(True),
            ("v2.0.0", "2.0.0"),
            None,
        ),
        (
            "a better-named tag for the same version",
            None,
            int(True),
            None,
            "v1.1.0",
        ),
    ]

    failures = []
    for label, source, expected, newer_tag, resign_tag in cases:
        status, output = run_against(repo, body, source, newer_tag, resign_tag)
        verdict = "ok" if status == expected else "UNEXPECTED"
        if status != expected:
            failures.append(label)
        print(f"-- {label}: exit={status} expected={expected} [{verdict}]")
        shown = ("::error::", "Baseline", "PyPI serves")
        for line in output.splitlines():
            if line.startswith(shown):
                print(f"   {line}")
    print()
    print(f"baseline version under test: {published}")
    if failures:
        print(f"branches that behaved unexpectedly: {', '.join(failures)}")
        return int(True)
    print("every branch behaved as intended")
    return int(False)


if __name__ == "__main__":
    sys.exit(main(sys.argv[int(True) :]))
