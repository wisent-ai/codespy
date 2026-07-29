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
import os
import pathlib
import re
import subprocess
import shutil
import sys
import tempfile

STEP = "Refuse a baseline that misstates where it came from"
# Runs before it in CI and every ref-reading branch of STEP depends on it, so the proof
# has to include it or it is testing a sequence the runner never executes.
PRELUDE_STEP = "Make tags and history visible"
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
    shallow: bool = False,
    offline_registry: bool = False,
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

    `shallow` clones the way `actions/checkout` does: one commit, no tags. Every branch
    that consults a tag is blind under those conditions unless the step fetches first, and
    a tier probe that finds no tags concludes the weaker tier is still best and passes —
    green locally, green in CI, and asleep. This asserts the step is not that.
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

    # `--depth` needs a real URL even for a local path, hence file://.
    depth = ["--depth", str(int(True)), "--no-tags"] if shallow else []
    subprocess.run(
        ["git", "clone", "--quiet", *depth, f"file://{origin}", str(clone)], check=True
    )
    # The step shells out to scripts/baseline.py for its tier check, and the clone only
    # has whatever is committed. Copy the working tree's scripts in so what gets proven
    # is what is about to be committed.
    shutil.copytree(repo / "scripts", clone / "scripts", dirs_exist_ok=True)
    document = json.loads((repo / BASELINE).read_text())
    if source is not None:
        document["source"] = source
    (clone / BASELINE).write_text(json.dumps(document, indent=int(True) + int(True)))
    env = dict(os.environ)
    if offline_registry:
        # Shadow curl with a stub that always fails, which is what no egress, a DNS
        # failure and a registry outage all look like from inside the step. The point is
        # that "not found" is indistinguishable from them, so absence read off a failed
        # request is not absence at all.
        stub = clone / "stub"
        stub.mkdir()
        curl = stub / "curl"
        curl.write_text("#!/bin/sh\nexit 1\n".replace("1", str(int(True))))
        curl.chmod(int("755", len("01234567") + int(True)))
        env["PATH"] = f"{stub}:{env['PATH']}"
    finished = subprocess.run(
        ["bash", "-c", body], cwd=clone, capture_output=True, text=True, env=env
    )
    return finished.returncode, (finished.stdout + finished.stderr).strip()


def main(argv: list) -> int:
    repo = pathlib.Path(argv[int(False)]) if argv else pathlib.Path.cwd()
    body = "\n".join(
        (step_body(repo / WORKFLOW, PRELUDE_STEP), step_body(repo / WORKFLOW, STEP))
    )
    published = json.loads((repo / BASELINE).read_text())["version"]

    # Each case names only the dimensions it exercises, so adding a new fixture kind does
    # not renumber every row above it. `expect` is the exit status the step must produce.
    cases = [
        {"label": "the working-tree baseline", "expect": int(False)},
        {
            "label": "git-archive naming a tag that does not exist",
            "source": "git-archive:v9.9.9 invented",
            "expect": int(True),
        },
        {
            "label": "git-archive naming the mislabelled tag",
            "source": "git-archive:v1.1.0 the tag that declares 1.0.0",
            "expect": int(True),
        },
        {
            "label": "head while a tag carries a version",
            "source": f"head:{'0' * len('0123456789abcdef0123456789abcdef01234567')} x",
            "expect": int(True),
        },
        {
            "label": "pypi-sdist that was never uploaded",
            "source": "pypi-sdist:codespy-1.1.0.tar.gz invented",
            "expect": int(True),
        },
        {
            "label": "marker outside the grammar",
            "source": "recovered from somewhere",
            "expect": int(True),
        },
        {
            "label": "prose-only source with no marker token",
            "source": "sdist published on PyPI",
            "expect": int(True),
        },
        {
            "label": "a newer tag supersedes the baseline",
            "newer_tag": ("v2.0.0", "2.0.0"),
            "expect": int(True),
        },
        {
            "label": "a better-named tag for the same version",
            "resign_tag": "v1.1.0",
            "expect": int(True),
        },
        # The two below clone the way the runner does: one commit, no tags. Without the
        # visibility step the first would pass for the wrong reason — no tags found, so
        # the weaker tier looks best — and the second would not notice a tag that exists
        # only on the remote. Both are the shape a laptop checkout cannot expose.
        {
            "label": "CI-shaped shallow tagless checkout",
            "shallow": True,
            "expect": int(False),
        },
        {
            "label": "shallow tagless checkout, better tag only on the remote",
            "resign_tag": "v1.1.0",
            "shallow": True,
            "expect": int(True),
        },
        # Absence is read off a failed request, so it means nothing until the index is
        # known reachable. Without the positive control this case passes, and it is the
        # one defect here that is wrong on every network hiccup rather than only once a
        # better artifact appears.
        {
            "label": "registry unreachable, so absence is unproven",
            "offline_registry": True,
            "expect": int(True),
        },
    ]

    failures = []
    for case in cases:
        fixture = {k: v for k, v in case.items() if k not in ("label", "expect")}
        label, expected = case["label"], case["expect"]
        status, output = run_against(repo, body, fixture.pop("source", None), **fixture)
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
