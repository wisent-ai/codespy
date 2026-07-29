#!/usr/bin/env python3
"""Regenerate released-surface.json from the best published artifact that exists.

The baseline is the yardstick every version decision is measured against, so it must
not be typed by hand. This resolves it, and it owns the provenance marker that couples
released-surface.json to the workflow — the marker is a constant here, referenced from
both sides, never prose either file greps for.

Provenance grammar, shared across the fleet. The marker is the first
whitespace-delimited token of "source"; everything after the first space is prose for
humans:

    pypi-sdist:<filename>    recovered from a published sdist
    pypi-wheel:<filename>    recovered from a published pure-Python wheel
    stado:<object path>      recovered from a published Stado channel artifact
    git-archive:<tag>        reproduced from a git tag with `git archive`
    head:<full sha>          last resort: nothing published and no usable tag

Tiers are tried best-first and the first one that actually exists wins. A lower tier is
never chosen because a higher one was inconvenient, and a tier this script does not
implement is refused loudly rather than skipped — silently dropping to a weaker tier
would measure every later change against the wrong artifact.

The version recorded is the LATEST PUBLISHED version, never the one codespy.py happens
to declare. Those differ the moment someone bumps ahead of a release, and looking up the
declared version would 404 and throw the real baseline away.

Usage:
    python3 scripts/baseline.py [--dry-run]
"""

from __future__ import annotations

import ast
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from http import HTTPStatus

sys.path.insert(int(False), str(pathlib.Path(__file__).resolve().parent))

import surface as extractor  # noqa: E402  the sibling extractor, reused not copied

PYPI_PROJECT = "codespy"
PYPI_JSON = f"https://pypi.org/pypi/{PYPI_PROJECT}/json"
BASELINE = "released-surface.json"
VERSION_NAME = "__version__"

MARKER_PYPI_SDIST = "pypi-sdist"
MARKER_PYPI_WHEEL = "pypi-wheel"
MARKER_STADO = "stado"
MARKER_GIT_ARCHIVE = "git-archive"
MARKER_HEAD = "head"

SDIST_TYPE = "sdist"
WHEEL_TYPE = "bdist_wheel"

INDENT = int(True) + int(True)


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def git(root: pathlib.Path, *args: str) -> str:
    finished = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    )
    return finished.stdout.strip()


def declared_version(source: str, origin: str) -> str:
    """The `__version__` a copy of the module declares, read with ast, never imported."""
    try:
        tree = ast.parse(source, filename=origin)
    except SyntaxError as error:
        raise SystemExit(f"{origin}: does not parse, so its version is unknown: {error}")
    for node in tree.body:
        targets = (
            [t for t in node.targets if isinstance(t, ast.Name)]
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
            else []
        )
        if not any(target.id == VERSION_NAME for target in targets):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    raise SystemExit(f"{origin}: no literal {VERSION_NAME}, so its version is unknown")


def pypi_project() -> dict | None:
    """The project's PyPI metadata, or None when PyPI does not serve it at all."""
    try:
        with urllib.request.urlopen(PYPI_JSON) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == HTTPStatus.NOT_FOUND:
            return None
        raise SystemExit(f"{PYPI_JSON}: {error}") from error
    except urllib.error.URLError as error:
        raise SystemExit(
            f"{PYPI_JSON}: {error}. Refusing rather than assuming nothing is published — "
            "an unreachable index looks identical to an unpublished project, and guessing "
            "would silently downgrade the baseline"
        ) from error


def newer(older: str, candidate: str) -> bool:
    """Ask the shared rule which version is newer; never reimplement the ordering."""
    finished = subprocess.run(
        ["autoversion", "order", "--older", older, "--newer", candidate, "--json"],
        capture_output=True,
        text=True,
    )
    if finished.returncode != int(False):
        raise SystemExit(
            "autoversion order failed; install the shared rule with "
            'pip install "git+https://github.com/lbartoszcze/AutoVersion@v0.1.0"'
        )
    return json.loads(finished.stdout)["is_newer"] == str(True)


def surface_of_tree(root: pathlib.Path) -> list:
    return extractor.surface(root)


def from_pypi(metadata: dict) -> tuple:
    """Marker, version and surface recovered from the latest published PyPI artifact."""
    version = metadata["info"]["version"]
    files = metadata["releases"].get(version) or []
    sdists = [f for f in files if f.get("packagetype") == SDIST_TYPE]
    if not sdists:
        wheels = [f for f in files if f.get("packagetype") == WHEEL_TYPE]
        if wheels:
            raise SystemExit(
                f"{PYPI_PROJECT} {version} is published as a wheel only. Recovering a "
                f"surface from a wheel is a tier this script does not implement yet; "
                f"add it rather than letting the baseline drop to a git tag"
            )
        raise SystemExit(
            f"{PYPI_PROJECT} {version} is on PyPI with no downloadable artifact, so its "
            "surface cannot be recovered"
        )
    chosen = min(sdists, key=lambda f: f["filename"])
    with urllib.request.urlopen(chosen["url"]) as response:
        payload = response.read()
    unpacked = pathlib.Path(tempfile.mkdtemp())
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        archive.extractall(unpacked)
    inner = [p for p in unpacked.iterdir() if p.is_dir()]
    root = min(inner, key=lambda p: p.name) if inner else unpacked
    return f"{MARKER_PYPI_SDIST}:{chosen['filename']}", version, surface_of_tree(root)


def tag_claims_full_version(tag: str) -> bool:
    """Whether the tag name itself asserts a complete version.

    `v1.1.0` claims one and can therefore be checked against its tree. `v1` does not:
    a floating major alias is the GitHub Action convention and is expected to move to
    the newest 1.x, so demanding that its name equal a full version would reject the
    very ref every README tells people to use.
    """
    stripped = tag.lstrip("v")
    parts = stripped.split(".")
    return len(parts) == len(("major", "minor", "patch")) and all(
        part.isdigit() for part in parts
    )


def from_git_tag(root: pathlib.Path) -> tuple | None:
    """Marker, version and surface of the newest tag that carries a real version.

    A tag is trusted only when the tree it points at agrees with it. A tag naming a full
    version whose tree declares something else is mis-signed: it is reported and skipped
    rather than filed under the version its name claims, because trusting the name would
    measure every later change against a tree that is not that release.

    Two trustworthy tags can name the same version — an alias like `v1` beside the
    `v1.1.0` it points at. The choice between them must be deterministic, or the tier
    check downstream flaps between two equally valid markers on consecutive runs. So the
    tie goes to the name that identifies the artifact most precisely: a full-version name
    is fixed, while an alias is expected to move, and comparing markers is only
    meaningful against a name that does not move. Remaining ties break by sorted name.
    """
    tags = sorted(t for t in git(root, "tag", "-l").splitlines() if t)
    best_tag, best_version = None, None
    for tag in tags:
        try:
            blob = git(root, "show", f"{tag}:{extractor.MODULE}")
        except subprocess.CalledProcessError:
            print(f"skipping tag {tag}: no {extractor.MODULE} in it", file=sys.stderr)
            continue
        version = declared_version(blob, f"{tag}:{extractor.MODULE}")
        if tag_claims_full_version(tag) and tag.lstrip("v") != version:
            print(
                f"skipping tag {tag}: it declares {version}, so the tag is mis-signed",
                file=sys.stderr,
            )
            continue
        if best_version is None or newer(best_version, version):
            best_tag, best_version = tag, version
        elif version == best_version and tag_claims_full_version(tag) \
                and not tag_claims_full_version(best_tag):
            best_tag = tag
    if best_tag is None:
        return None
    unpacked = pathlib.Path(tempfile.mkdtemp())
    archive = subprocess.run(
        ["git", "archive", best_tag], cwd=root, capture_output=True, check=True
    )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(unpacked)
    return f"{MARKER_GIT_ARCHIVE}:{best_tag}", best_version, surface_of_tree(unpacked)


def from_head(root: pathlib.Path) -> tuple:
    sha = git(root, "rev-parse", "HEAD")
    version = declared_version(
        (root / extractor.MODULE).read_text(), str(root / extractor.MODULE)
    )
    return f"{MARKER_HEAD}:{sha}", version, surface_of_tree(root)


def resolve(root: pathlib.Path) -> tuple:
    """The best tier that exists, and prose explaining why the weaker ones do not."""
    metadata = pypi_project()
    if metadata is not None:
        marker, version, names = from_pypi(metadata)
        return marker, version, names, (
            f"the latest version PyPI serves for {PYPI_PROJECT}, unpacked and read by "
            "scripts/surface.py. This is the artifact users install, so no weaker tier "
            "applies."
        )

    tagged = from_git_tag(root)
    if tagged is not None:
        marker, version, names = tagged
        tag = marker.split(":").pop()
        return marker, version, names, (
            f"reproduced with `git archive {tag}` and read by scripts/surface.py. PyPI "
            f"serves no project named {PYPI_PROJECT} at all, and codespy ships no "
            "packaging metadata, so no sdist or wheel exists to prefer; it does not ship "
            "through Stado either. It is published as a GitHub Action, and every README "
            f"example consumes wisent-ai/codespy@{tag}, so this tag is the artifact "
            f"callers actually get, and its {extractor.MODULE} declares {version}. Note "
            "the tag literally named v1.1.0 points at the earlier 239f664, whose "
            f"{extractor.MODULE} still declares 1.0.0; it is mislabelled and is not the "
            "baseline."
        )

    marker, version, names = from_head(root)
    return marker, version, names, (
        f"last resort. PyPI serves no project named {PYPI_PROJECT}, and no git tag "
        f"carries a readable {extractor.MODULE}, so nothing is published and there is no "
        "higher tier to reach for."
    )


def main(argv: list) -> int:
    root = repo_root()
    marker, version, names, prose = resolve(root)
    document = {
        "version": version,
        "source": f"{marker} {prose}",
        "surface": names,
    }
    rendered = json.dumps(document, indent=INDENT) + "\n"
    if "--stdout" in argv:
        # For the workflow's tier check: it needs to know which tier is reachable now
        # without the committed baseline being touched. Only the marker may be read from
        # this; letting the regenerated *surface* reach the decision would recompute both
        # sides at check time, which is the one shape that structurally cannot refuse.
        sys.stdout.write(rendered)
        return int(False)
    if "--dry-run" in argv:
        print(f"{marker}  version={version}  names={len(names)}")
        return int(False)
    (root / BASELINE).write_text(rendered)
    print(f"wrote {BASELINE}: {marker}, version {version}, {len(names)} names")
    return int(False)


if __name__ == "__main__":
    sys.exit(main(sys.argv[int(True) :]))
