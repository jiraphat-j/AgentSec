"""Pure bounded queries over an immutable dashboard catalog."""

from __future__ import annotations

from copy import deepcopy

from .constants import MAX_DASHBOARD_PAGE_SIZE
from .dashboard_catalog import CatalogRecord, DashboardCatalog, safe_event
from .dashboard_models import ArtifactKind


class DashboardNotFoundError(LookupError):
    """Raised when an opaque catalog identity is absent."""


class DashboardQueryError(ValueError):
    """Raised when a dashboard query is outside its closed contract."""


class DashboardService:
    def __init__(self, catalog: DashboardCatalog) -> None:
        self._catalog = catalog

    @staticmethod
    def _page(values: list[dict[str, object]], offset: int, limit: int) -> dict[str, object]:
        if offset < 0 or limit < 1 or limit > MAX_DASHBOARD_PAGE_SIZE:
            raise DashboardQueryError("invalid pagination")
        return {
            "items": values[offset : offset + limit],
            "total": len(values),
            "offset": offset,
            "limit": limit,
        }

    def catalog(self, offset: int, limit: int) -> dict[str, object]:
        values = [record.summary.model_dump(mode="json") for record in self._catalog.records]
        return self._page(values, offset, limit)

    def list_kind(
        self, kinds: tuple[ArtifactKind, ...], offset: int, limit: int
    ) -> dict[str, object]:
        values = [
            record.summary.model_dump(mode="json") for record in self._catalog.by_kind(*kinds)
        ]
        return self._page(values, offset, limit)

    def detail(self, item_id: str, kinds: tuple[ArtifactKind, ...]) -> dict[str, object]:
        record = self._record(item_id, kinds)
        data = deepcopy(record.data)
        nested: dict[str, int] = {}
        if record.summary.kind is ArtifactKind.INVESTIGATION:
            for key, name in (
                ("derived_alerts", "alerts"),
                ("incidents", "incidents"),
                ("rule_evaluations", "rule-evaluations"),
            ):
                values = data.pop(key, [])
                nested[name] = len(values) if isinstance(values, list) else 0
        elif record.summary.kind is ArtifactKind.EVALUATION:
            for key, name in (
                ("children", "children"),
                ("metrics", "metrics"),
                ("pairs", "pairs"),
                ("confusion_counts", "confusion-counts"),
                ("timing", "timing"),
            ):
                values = data.pop(key, [])
                nested[name] = len(values) if isinstance(values, list) else 0
        elif record.summary.kind is ArtifactKind.RUN_REPORT:
            values = data.pop("timeline", [])
            nested["timeline"] = len(values) if isinstance(values, list) else 0
        if nested:
            data["nested_collection_counts"] = nested
        return {
            "summary": record.summary.model_dump(mode="json"),
            "data": data,
        }

    def nested(
        self,
        item_id: str,
        kind: ArtifactKind,
        collection: str,
        offset: int,
        limit: int,
    ) -> dict[str, object]:
        if kind not in {ArtifactKind.INVESTIGATION, ArtifactKind.EVALUATION}:
            raise DashboardNotFoundError("nested collection not found")
        record = self._record(item_id, (kind,))
        keys = {
            ArtifactKind.INVESTIGATION: {
                "alerts": "derived_alerts",
                "incidents": "incidents",
                "rule-evaluations": "rule_evaluations",
            },
            ArtifactKind.EVALUATION: {
                "children": "children",
                "metrics": "metrics",
                "pairs": "pairs",
                "confusion-counts": "confusion_counts",
                "timing": "timing",
            },
        }
        key = keys[record.summary.kind].get(collection)
        values = record.data.get(key) if key is not None else None
        if not isinstance(values, list):
            raise DashboardNotFoundError("nested collection not found")
        return self._page([deepcopy(value) for value in values], offset, limit)

    def events(
        self,
        run_id: str,
        offset: int,
        limit: int,
        *,
        trace_id: str | None = None,
        event_type: str | None = None,
    ) -> dict[str, object]:
        record = self._record(run_id, (ArtifactKind.EVENT_SOURCE,))
        if trace_id is not None and (not trace_id or len(trace_id) > 96):
            raise DashboardQueryError("invalid trace filter")
        if event_type is not None and (not event_type or len(event_type) > 96):
            raise DashboardQueryError("invalid event-type filter")
        values = [
            safe_event(event)
            for event in record.events
            if (trace_id is None or event.trace_id == trace_id)
            and (event_type is None or event.event_type == event_type)
        ]
        return self._page(values, offset, limit)

    def event(self, run_id: str, event_id: str) -> dict[str, object]:
        record = self._record(run_id, (ArtifactKind.EVENT_SOURCE,))
        event = next((event for event in record.events if event.event_id == event_id), None)
        if event is None:
            raise DashboardNotFoundError("event not found")
        return safe_event(event)

    def report_timeline(self, item_id: str, offset: int, limit: int) -> dict[str, object]:
        record = self._record(item_id, (ArtifactKind.RUN_REPORT,))
        values = record.data.get("timeline")
        if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
            raise DashboardNotFoundError("report timeline not found")
        return self._page([deepcopy(value) for value in values], offset, limit)

    def investigation_child(
        self, item_id: str, collection: str, child_id: str
    ) -> dict[str, object]:
        record = self._record(item_id, (ArtifactKind.INVESTIGATION,))
        key = "derived_alerts" if collection == "alerts" else "incidents"
        values = record.data.get(key)
        if not isinstance(values, list):
            raise DashboardNotFoundError("collection not found")
        prefix = "alert" if collection == "alerts" else "incident"
        if not child_id.startswith(f"{prefix}-") or not child_id[len(prefix) + 1 :].isdigit():
            raise DashboardNotFoundError("item not found")
        index = int(child_id[len(prefix) + 1 :])
        if index >= len(values):
            raise DashboardNotFoundError("item not found")
        value = values[index]
        if not isinstance(value, dict):
            raise DashboardNotFoundError("item not found")
        return {"id": child_id, **deepcopy(value)}

    def _record(self, item_id: str, kinds: tuple[ArtifactKind, ...]) -> CatalogRecord:
        record = self._catalog.get(item_id)
        if record is None or record.summary.kind not in kinds:
            raise DashboardNotFoundError("catalog item not found")
        return record
