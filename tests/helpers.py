from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime


def sequential_ids() -> Callable[[str], str]:
    counts: defaultdict[str, int] = defaultdict(int)

    def create(prefix: str) -> str:
        counts[prefix] += 1
        return f"{prefix}_{counts[prefix]}"

    return create


def fixed_clock() -> datetime:
    return datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
