"""Test-only G0 capture races and post-capture snapshot isolation."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import IO, Any, cast

import pytest

import agentsec.dashboard_catalog as catalog_module
from agentsec.dashboard_catalog import DashboardCatalog, DashboardInputError
from agentsec.dashboard_models import ArtifactKind
from agentsec.dashboard_service import DashboardService
from agentsec.replay import ReplayEvidence, read_replay_evidence

from .test_dashboard_g0_boundaries import write_manifest, write_rule_test, write_source


class ReadHook:
    """Observe a real descriptor read and inject a single synthetic-file mutation."""

    def __init__(self, handle: IO[Any], after_read: Callable[[], None]) -> None:
        self.handle = handle
        self.after_read = after_read
        self.read_sizes: list[int] = []

    def __enter__(self) -> ReadHook:
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.handle.close()

    def fileno(self) -> int:
        return self.handle.fileno()

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        data = self.handle.read(size)
        assert isinstance(data, bytes)
        self.after_read()
        return data


def mutate(path: Path, replacement: Path, variant: str) -> None:
    if variant == "append":
        with path.open("ab") as handle:
            handle.write(b" ")
    elif variant == "touch":
        value = path.stat()
        os.utime(path, ns=(value.st_atime_ns, value.st_mtime_ns + 1_000_000_000))
    elif variant == "replace":
        replacement.replace(path)
    elif variant == "delete":
        path.unlink()
    elif variant == "symlink":
        path.unlink()
        path.symlink_to(replacement)
    else:
        raise AssertionError("unknown test mutation")


@pytest.mark.parametrize("target", ["manifest", "report"])
@pytest.mark.parametrize("variant", ["append", "touch", "replace", "delete", "descriptor"])
def test_public_json_loader_rejects_capture_races_and_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    variant: str,
) -> None:
    if os.name == "nt" and variant in {"replace", "delete"}:
        pytest.skip("Unix open-descriptor replacement/deletion; Windows sharing semantics differ")
    artifact = tmp_path / "report.json"
    write_rule_test(artifact)
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": artifact.name}])
    assert DashboardCatalog.load(manifest).get("report") is not None
    selected = manifest if target == "manifest" else artifact
    raw = selected.read_bytes()
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(raw)
    identity = selected.stat()
    os.utime(replacement, ns=(identity.st_atime_ns, identity.st_mtime_ns))
    # Isolate inode identity: bytes, size and mtime are identical, not malformed input.
    assert replacement.stat().st_size == identity.st_size
    assert replacement.stat().st_mtime_ns == identity.st_mtime_ns
    assert replacement.stat().st_ino != selected.stat().st_ino
    original_open = Path.open
    hooks: list[ReadHook] = []

    def open_with_hook(
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> IO[Any]:
        if path != selected or mode != "rb":
            return original_open(path, mode, buffering, encoding, errors, newline)
        handle = original_open(replacement if variant == "descriptor" else path, mode)
        hook = ReadHook(handle, lambda: mutate(selected, replacement, variant))
        hooks.append(hook)
        return cast(IO[Any], hook)

    monkeypatch.setattr(Path, "open", open_with_hook)
    message = "unable to inspect" if variant == "delete" else "changed during dashboard startup"
    with pytest.raises(DashboardInputError, match=message):
        DashboardCatalog.load(manifest)
    assert len(hooks) == 1 and hooks[0].handle.closed
    if variant == "descriptor":
        assert hooks[0].read_sizes == []  # Reject wrong descriptor before reading its data.
    else:
        assert len(hooks[0].read_sizes) == 1 and hooks[0].read_sizes[0] > len(raw)
    if variant in {"replace", "descriptor"}:
        with original_open(selected, "rb") as handle:
            assert handle.read() == raw


@pytest.mark.parametrize("variant", ["touch", "replace", "delete", "symlink"])
def test_sqlite_capture_rejects_identity_changes_after_read_and_closes_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    if variant == "symlink" and os.name == "nt":
        pytest.skip("Linux symlink substitution; Windows reparse evidence remains separate")
    source = tmp_path / "events.sqlite3"
    write_source(source, tool="read_file")
    raw = source.read_bytes()
    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(raw)
    manifest = tmp_path / "manifest.json"
    write_manifest(
        manifest, [{"id": "source", "kind": "event_source", "path": source.name, "run_id": "run_1"}]
    )
    assert DashboardCatalog.load(manifest).get("source") is not None
    identity = source.stat()
    os.utime(replacement, ns=(identity.st_atime_ns, identity.st_mtime_ns))
    assert replacement.stat().st_size == identity.st_size
    assert replacement.stat().st_mtime_ns == identity.st_mtime_ns
    assert replacement.stat().st_ino != identity.st_ino
    original_connect = sqlite3.connect
    closed: list[sqlite3.Connection] = []
    statements: list[str] = []

    class TrackedConnection(sqlite3.Connection):
        def close(self) -> None:
            super().close()
            closed.append(self)

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        assert kwargs.get("uri") is True and str(args[0]).endswith("?mode=ro")
        connection = original_connect(*args, **kwargs, factory=TrackedConnection)
        connection.set_trace_callback(statements.append)
        return connection

    original_read = read_replay_evidence
    calls = 0

    def read_then_mutate(path: Path, run_id: str) -> ReplayEvidence:
        nonlocal calls
        evidence = original_read(path, run_id)
        assert len(closed) == 1  # Reader releases connection before identity recheck.
        calls += 1
        mutate(path, replacement, variant)
        return evidence

    monkeypatch.setattr(sqlite3, "connect", connect)
    monkeypatch.setattr(catalog_module, "read_replay_evidence", read_then_mutate)
    message = {"delete": "unable to inspect", "symlink": "link or reparse"}.get(
        variant, "changed during dashboard startup"
    )
    with pytest.raises(DashboardInputError, match=message):
        DashboardCatalog.load(manifest)
    assert calls == len(closed) == 1
    assert "PRAGMA query_only = ON" in statements
    assert all(
        statement.lstrip().upper().startswith(("SELECT", "PRAGMA", "BEGIN"))
        for statement in statements
    )
    if variant in {"replace", "touch", "symlink"}:
        assert source.read_bytes() == raw


@pytest.mark.parametrize("variant", ["replace", "delete", "append"])
def test_service_uses_captured_data_without_reopening_changed_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    source = tmp_path / "events.sqlite3"
    write_source(source, tool="read_file")
    report = tmp_path / "report.json"
    write_rule_test(report)
    manifest = tmp_path / "manifest.json"
    write_manifest(
        manifest,
        [
            {"id": "source", "kind": "event_source", "path": source.name, "run_id": "run_1"},
            {"id": "report", "kind": "rule_test", "path": report.name},
        ],
    )
    catalog = DashboardCatalog.load(manifest)
    source_record = catalog.get("source")
    assert source_record is not None
    service = DashboardService(catalog)
    before = [
        service.catalog(0, 10),
        service.events("source", 0, 10),
        service.detail("report", (ArtifactKind.RULE_TEST,)),
    ]
    original_source = source.read_bytes()
    replacement_source = tmp_path / "replacement.sqlite3"
    write_source(replacement_source, tool="http_post")
    replacement_report = tmp_path / "replacement.json"
    raw = json.loads(report.read_bytes())
    raw["status"] = "failed"
    replacement_report.write_text(json.dumps(raw), encoding="utf-8")
    for path, replacement in ((source, replacement_source), (report, replacement_report)):
        mutate(path, replacement, variant)
    after_mutation = {path: path.read_bytes() for path in (source, report) if path.exists()}
    assert not source.exists() or source.read_bytes() != original_source

    def no_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("in-memory service reopened selected files")

    with monkeypatch.context() as context:
        context.setattr(Path, "open", no_read)
        context.setattr(catalog_module, "read_replay_evidence", no_read)
        assert [
            service.catalog(0, 10),
            service.events("source", 0, 10),
            service.detail("report", (ArtifactKind.RULE_TEST,)),
        ] == before
        assert service.event("source", source_record.events[-1].event_id)["payload"] == {
            "tool": "read_file"
        }
    assert all(path.read_bytes() == raw for path, raw in after_mutation.items())
    # This proves captured-snapshot semantics, not continued authentication of mutable input files.
