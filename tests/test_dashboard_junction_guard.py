"""Data-only checks of junction command arguments; no shell or filesystem operations."""

from __future__ import annotations

import pytest

from .test_dashboard_g0_boundaries import _windows_junction_args


@pytest.mark.parametrize(
    ("junction", "target"),
    [
        (r"C:\tmp\dashboard\linked", r"C:\tmp\outside"),
        (
            r"C:\Users\runneradmin\AppData\Local\Temp\pytest-0\test_junction_0\dashboard\linked",
            r"C:\Users\runneradmin\AppData\Local\Temp\pytest-0\test_junction_0\outside",
        ),
        (r"d:\temp-root\pytest_1\dashboard\linked", r"d:\temp-root\pytest_1\outside"),
    ],
    ids=["simple", "ci-shaped", "lowercase-drive"],
)
def test_junction_args_accept_plain_absolute_drive_paths(junction: str, target: str) -> None:
    expected = ["cmd", "/d", "/c", "mklink", "/J", junction, target]
    assert _windows_junction_args(junction, target) == expected


@pytest.mark.parametrize("position", [0, 1], ids=["junction", "target"])
@pytest.mark.parametrize(
    "unsafe_path",
    [
        pytest.param(r"C:\tmp&marker\node", id="ampersand"),
        pytest.param(r"C:\tmp|marker\node", id="pipe"),
        pytest.param(r"C:\tmp%MARKER%\node", id="percent-expansion"),
        pytest.param(r"C:\tmp!MARKER!\node", id="delayed-expansion"),
        pytest.param(r"C:\tmp^marker\node", id="escape"),
        pytest.param(r"C:\tmp(marker)\node", id="parentheses"),
        pytest.param('C:\\tmp"marker\\node', id="quote"),
        pytest.param(r"C:\tmp>marker\node", id="redirection"),
        pytest.param(r"C:\temp root\node", id="space"),
        pytest.param("C:\\tmp\nmarker\\node", id="newline"),
        pytest.param("C:\\tmp\u00e9\\node", id="unicode"),
        pytest.param(r"C:relative\node", id="drive-relative"),
        pytest.param(r"relative\node", id="relative"),
        pytest.param(r"\\server\share\node", id="unc"),
        pytest.param(r"\\?\C:\tmp\node", id="device-path"),
    ],
)
def test_junction_args_reject_unsafe_path_in_either_position(
    unsafe_path: str, position: int
) -> None:
    paths = [r"C:\tmp\dashboard\linked", r"C:\tmp\outside"]
    paths[position] = unsafe_path
    with pytest.raises(ValueError, match="absolute ASCII drive paths"):
        _windows_junction_args(*paths)
