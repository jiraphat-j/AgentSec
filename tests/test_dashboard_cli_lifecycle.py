"""A2 draft: run only after concrete human review in the networkless Linux sandbox."""

from __future__ import annotations

import errno
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentsec.cli import main
from agentsec.dashboard_catalog import DashboardCatalog
from agentsec.dashboard_service import DashboardService

pytestmark = [
    pytest.mark.dashboard_lifecycle,
    pytest.mark.skipif(sys.platform != "linux", reason="Windows console evidence is separate"),
]

MARKER = "synthetic-cli-lifecycle-marker"
CAPTURE_LIMIT = 65536
EXPECTED_CATALOG = {
    "items": [
        {
            "id": "artifact",
            "kind": "rule_test",
            "provenance": "report_only",
            "title": "Rule Test artifact",
            "status": "failed",
        }
    ],
    "total": 1,
    "offset": 0,
    "limit": 50,
}


@pytest.fixture(autouse=True)
def require_approved_sandbox() -> None:
    # The token prevents accidental execution; the reviewed bwrap wrapper supplies isolation.
    assert os.environ.get("AGENTSEC_DASHBOARD_LIFECYCLE_SANDBOX") == "networkless-bwrap-v1"
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in Path("/proc/net/dev").read_text().splitlines()
        if ":" in line
    }
    assert interfaces == {"lo"}, "expected only private loopback, not a host interface"


@pytest.fixture
def manifest(tmp_path: Path) -> Iterator[Path]:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    artifact = inputs / "artifact.json"
    artifact.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "failed",
                "total_rules": 1,
                "covered_rules": 0,
                "assertions_passed": 0,
                "assertions_total": 1,
                "results": [
                    {
                        "fixture": MARKER,
                        "rule_id": "ASL-TEST-001",
                        "rule_version": 1,
                        "passed": False,
                        "expected_evidence": [],
                        "actual_evidence": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    selected = inputs / "manifest.json"
    selected.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [{"id": "artifact", "kind": "rule_test", "path": artifact.name}],
            }
        ),
        encoding="utf-8",
    )
    before = {path.name: path.read_bytes() for path in inputs.iterdir()}
    yield selected
    assert {path.name: path.read_bytes() for path in inputs.iterdir()} == before


def _pids() -> set[int]:
    # /proc is mounted inside the reviewed private PID namespace; never inspect host /proc.
    return {int(path.name) for path in Path("/proc").iterdir() if path.name.isdecimal()}


def _cleanup(process: subprocess.Popen[bytes]) -> None:
    if sys.platform != "linux":
        raise RuntimeError("process-group lifecycle tests require Linux")
    # Only the session/process group created by this Popen is eligible for cleanup.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    # A reaped leader does not imply its descendants stopped. Escalate only this owned group.
    deadline = time.monotonic() + 2
    while _group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    if _group_exists(process.pid):
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)


def _group_exists(group: int) -> bool:
    if sys.platform != "linux":
        raise RuntimeError("process-group lifecycle tests require Linux")
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


@contextmanager
def _cli(manifest: Path, port: int) -> Iterator[subprocess.Popen[bytes]]:
    baseline = _pids()
    log_root = manifest.parent.parent
    with (
        (log_root / "stdout.log").open("wb") as stdout,
        (log_root / "stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agentsec",
                "dashboard",
                "--manifest",
                str(manifest),
                "--port",
                str(port),
            ],
            cwd="/work",
            env={
                "HOME": "/tmp",
                "TMPDIR": "/tmp",
                "PATH": "/sandbox/venv/bin:/usr/bin:/bin",
                "PYTHONPATH": "/work/src:/work",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            start_new_session=True,
        )
        try:
            yield process
            assert process.poll() is not None, "test did not stop its CLI child"
            deadline = time.monotonic() + 2
            while _pids() != baseline and time.monotonic() < deadline:
                time.sleep(0.02)
            assert _pids() == baseline, "CLI left a child process in the private namespace"
        finally:
            _cleanup(process)
    for name in ("stdout.log", "stderr.log"):
        captured = log_root / name
        assert captured.stat().st_size <= CAPTURE_LIMIT
        text = captured.read_text(encoding="utf-8")
        assert MARKER not in text
        assert "Traceback" not in text


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _assert_listener_closed(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", port)) == errno.ECONNREFUSED
        # Uvicorn also uses SO_REUSEADDR; allow TIME_WAIT, not a live listener.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))


def _wait_for_catalog(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        assert process.poll() is None, "CLI exited before serving the catalog"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
        try:
            connection.request("GET", "/api/v1/catalog")
            response = connection.getresponse()
            body = response.read(CAPTURE_LIMIT + 1)
            assert len(body) <= CAPTURE_LIMIT
            assert response.status == 200
            assert json.loads(body) == EXPECTED_CATALOG
            assert response.getheader("cache-control") == "no-store"
            assert response.getheader("x-content-type-options") == "nosniff"
            assert MARKER.encode() not in body
            return
        except ConnectionRefusedError:
            time.sleep(0.02)
        finally:
            connection.close()
    pytest.fail("CLI did not serve the genuine catalog within 15 seconds")


def test_dashboard_cli_normal_return(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, object]] = []

    def run(app: FastAPI, **kwargs: object) -> None:
        calls.append(kwargs)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            response = client.get("/api/v1/catalog")
            assert response.status_code == 200
            assert response.json() == EXPECTED_CATALOG

    monkeypatch.setattr("uvicorn.run", run)
    assert main(["dashboard", "--manifest", str(manifest), "--port", "8765"]) == 0
    assert calls == [
        {"host": "127.0.0.1", "port": 8765, "reload": False, "workers": 1, "access_log": False}
    ]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_dashboard_cli_occupied_port(manifest: Path) -> None:
    # Validate the same input through the public loader before testing a genuine bind failure.
    assert DashboardService(DashboardCatalog.load(manifest)).catalog(0, 50) == EXPECTED_CATALOG
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        address = blocker.getsockname()
        port = int(address[1])
        with _cli(manifest, port) as process:
            assert process.wait(timeout=10) == 3, "expected Uvicorn startup-failure exit"
        assert "address already in use" in (manifest.parent.parent / "stderr.log").read_text()
        assert blocker.getsockname() == address
        assert blocker.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    _assert_listener_closed(port)


def test_dashboard_cli_foreground_interrupt(manifest: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeError("process-group lifecycle tests require Linux")
    port = _unused_port()
    with _cli(manifest, port) as process:
        _wait_for_catalog(process, port)
        os.killpg(process.pid, signal.SIGINT)
        assert process.wait(timeout=10) == 0, "foreground SIGINT did not return cleanly"
        _assert_listener_closed(port)
