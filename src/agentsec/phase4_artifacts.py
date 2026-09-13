"""Exclusive, bounded two-file publication for Phase 4 derived reports."""

from __future__ import annotations

import os
from pathlib import Path

from .constants import MAX_REPORT_BYTES
from .reporting import ReportWriteError
from .resource_loader import load_canary


def publish_report_pair(
    directory: Path, stem: str, json_data: bytes, markdown_data: bytes
) -> tuple[Path, Path]:
    """Stage both files, then link without replacing any existing artifact."""
    files = ((directory / f"{stem}.json", json_data), (directory / f"{stem}.md", markdown_data))
    if any(path.exists() for path, _ in files):
        raise ReportWriteError(f"refusing to overwrite an existing {stem} report")
    canary = load_canary().encode("utf-8")
    if any(canary in data for _, data in files):
        raise ReportWriteError(f"raw lab canary rejected from {stem} report")
    if any(len(data) > MAX_REPORT_BYTES for _, data in files):
        raise ReportWriteError(f"{stem} report exceeds fixed size limit")

    owned: list[Path] = []
    staged: list[Path] = []
    try:
        for path, data in files:
            temporary = directory / f".{path.name}.tmp"
            with temporary.open("xb") as handle:
                owned.append(temporary)
                handle.write(data)
            staged.append(temporary)
        for temporary, (path, _) in zip(staged, files, strict=True):
            os.link(temporary, path)
            owned.append(path)
        for temporary in staged:
            temporary.unlink()
            owned.remove(temporary)
    except OSError as error:
        for path in reversed(owned):
            try:
                path.unlink()
            except OSError as cleanup_error:
                error.add_note(f"{stem} cleanup failed: {type(cleanup_error).__name__}")
        raise ReportWriteError(f"unable to write required {stem} artifacts") from error
    return files[0][0], files[1][0]
