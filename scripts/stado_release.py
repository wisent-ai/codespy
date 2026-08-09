from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile

EPOCH = 946684800
EXCLUDED = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def source_dir() -> Path:
    path = Path(required("WISENT_SOURCE_DIR")).resolve()
    if not path.is_dir():
        raise SystemExit(f"WISENT_SOURCE_DIR is not a directory: {path}")
    return path


def output_dir() -> Path:
    path = Path(required("WISENT_OUTPUT_DIR")).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def declared_version(root: Path) -> str:
    released = root / "released-surface.json"
    if released.is_file():
        value = json.loads(released.read_text(encoding="utf-8")).get("version")
        if isinstance(value, str) and value:
            return value
    codespy = root / "codespy.py"
    if codespy.is_file():
        matches = re.findall(r'^__version__\s*=\s*["\']([^"\']+)["\']', codespy.read_text(encoding="utf-8"), re.MULTILINE)
        if len(matches) == 1:
            return matches[0]
    raise SystemExit("source product has no unique declared version")


def quality() -> None:
    if declared_version(source_dir()) != required("WISENT_VERSION"):
        raise SystemExit("WISENT_VERSION does not match the source product")
    required("WISENT_PLATFORM")
    required("WISENT_INPUTS_DIR")


def source_files(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file() and not any(part in EXCLUDED for part in path.relative_to(root).parts)),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def add_file(archive: tarfile.TarFile, path: Path, name: str) -> None:
    info = archive.gettarinfo(str(path), arcname=name)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = EPOCH
    with path.open("rb") as handle:
        archive.addfile(info, handle)


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    import io
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = EPOCH
    archive.addfile(info, io.BytesIO(data))


def build() -> None:
    quality()
    root = source_dir()
    files = source_files(root)
    if not files:
        raise SystemExit("source product is empty")
    metadata = {
        "product": required("WISENT_PRODUCT"),
        "version": required("WISENT_VERSION"),
        "files": {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    }
    release = output_dir() / "release"
    shutil.rmtree(release, ignore_errors=True)
    release.mkdir(parents=True)
    with tarfile.open(release / "source-bundle.tar", "w", format=tarfile.PAX_FORMAT) as archive:
        for path in files:
            add_file(archive, path, f"source/{path.relative_to(root).as_posix()}")
        add_bytes(archive, "output/build-metadata.json", json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("quality", "build"))
    args = parser.parse_args()
    {"quality": quality, "build": build}[args.command]()


if __name__ == "__main__":
    main()
