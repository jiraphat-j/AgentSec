"""Bounded, confined loading of read-only dashboard artifacts."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from time import monotonic
from typing import Any

from pydantic import BaseModel, ValidationError

from .constants import (
    MAX_DASHBOARD_EVENTS,
    MAX_DASHBOARD_INPUT_BYTES,
    MAX_DASHBOARD_MANIFEST_BYTES,
    MAX_DASHBOARD_PROJECTION_BYTES,
    MAX_DASHBOARD_RUNS,
    MAX_DASHBOARD_STARTUP_SECONDS,
    MAX_REPORT_BYTES,
    MAX_RULE_BYTES,
)
from .dashboard_models import (
    ArtifactKind,
    CatalogSummary,
    DashboardManifest,
    DashboardManifestEntry,
    Provenance,
)
from .detection import CorrelationDetector
from .evaluation_models import EvaluationReport
from .evidence import fingerprint_snapshot, validate_snapshot
from .incident_models import EvidenceReference, InvestigationReport
from .models import ComparisonReport, Event, Report
from .replay import ReplayEvidence, read_replay_evidence
from .reporting import build_report
from .resource_loader import load_canary, load_scenario
from .rule_models import DetectionRule, ReplayReport, RuleTestReport


class DashboardInputError(ValueError):
    """Raised when selected dashboard data is invalid or inconsistent."""


class DashboardResourceLimitExceeded(RuntimeError):
    """Raised when dashboard startup exceeds a fixed resource bound."""


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    summary: CatalogSummary
    data: dict[str, object]
    events: tuple[Event, ...] = ()
    snapshot_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


_REPORT_MODELS: dict[ArtifactKind, type[BaseModel]] = {
    ArtifactKind.RUN_REPORT: Report,
    ArtifactKind.COMPARISON: ComparisonReport,
    ArtifactKind.REPLAY: ReplayReport,
    ArtifactKind.INVESTIGATION: InvestigationReport,
    ArtifactKind.EVALUATION: EvaluationReport,
    ArtifactKind.RULE: DetectionRule,
    ArtifactKind.RULE_TEST: RuleTestReport,
}

_SAFE_PAYLOAD_FIELDS: dict[str, frozenset[str]] = {
    "run.started": frozenset({"scenario_id", "fixture", "profile", "policy_version"}),
    "run.completed": frozenset({"detected", "prevented", "simulated_impact"}),
    "run.failed": frozenset({"error_type"}),
    "agent.context.document_added": frozenset({"document_id", "source", "trust"}),
    "tool.requested": frozenset({"tool"}),
    "policy.evaluated": frozenset({"tool", "profile", "policy_id", "policy_version", "risk"}),
    "policy.allowed": frozenset(
        {"tool", "profile", "policy_id", "policy_version", "decision", "reason", "risk"}
    ),
    "policy.denied": frozenset(
        {
            "tool",
            "profile",
            "policy_id",
            "policy_version",
            "decision",
            "reason",
            "enforcement_layer",
            "risk",
        }
    ),
    "policy.approval_required": frozenset({"tool", "profile", "policy_version", "risk"}),
    "approval.simulated": frozenset({"approved", "reason", "policy_version"}),
    "tool.executed": frozenset({"tool"}),
    "tool.failed": frozenset({"tool", "error_type"}),
    "file.read": frozenset({"classification", "canary_id", "value_sha256"}),
    "lab.sink.payload_recorded": frozenset(
        {"canary_id", "value_sha256", "observed_in", "redacted", "matched"}
    ),
    "detection.match": frozenset({"rule_id", "rule_version", "severity", "evidence_event_ids"}),
    "alert.created": frozenset({"alert_id", "rule_id", "rule_version", "severity"}),
    "incident.created": frozenset({"incident_id", "alert_id", "severity"}),
    "report.created": frozenset({"formats"}),
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DashboardInputError("JSON contains duplicate object keys")
        result[key] = value
    return result


def _load_json(data: bytes) -> object:
    def reject_nonfinite(_value: str) -> object:
        raise DashboardInputError("JSON contains a non-finite number")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DashboardInputError("artifact is not valid UTF-8 JSON") from error


def _validate_json_model[ModelT: BaseModel](model: type[ModelT], data: bytes) -> ModelT:
    # Python-mode strict validation correctly rejects coercion at internal call sites,
    # while JSON mode accepts JSON arrays/strings for tuple and enum fields.
    _load_json(data)
    return model.model_validate_json(data)


def _identity(path: Path) -> _FileIdentity:
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as error:
        raise DashboardInputError("unable to inspect selected artifact") from error
    if not stat.S_ISREG(value.st_mode):
        raise DashboardInputError("selected artifact is not a regular file")
    return _FileIdentity(value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _same_identity(value: os.stat_result, expected: _FileIdentity) -> bool:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    ) == (expected.device, expected.inode, expected.size, expected.modified_ns)


def _verify_path_identity(path: Path, root: Path, expected: _FileIdentity) -> None:
    relative = path.relative_to(root).as_posix()
    checked = _resolve_artifact(
        root,
        DashboardManifestEntry(id="identity-check", kind=ArtifactKind.RULE, path=relative),
    )
    if checked != path or _identity(path) != expected:
        raise DashboardInputError("selected artifact changed during dashboard startup")


def _guarded_read(path: Path, root: Path, expected: _FileIdentity, limit: int) -> bytes:
    _verify_path_identity(path, root, expected)
    try:
        with path.open("rb") as handle:
            if not _same_identity(os.fstat(handle.fileno()), expected):
                raise DashboardInputError("selected artifact changed during dashboard startup")
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise DashboardResourceLimitExceeded("selected artifact exceeds its fixed limit")
            if not _same_identity(os.fstat(handle.fileno()), expected):
                raise DashboardInputError("selected artifact changed during dashboard startup")
    except OSError as error:
        raise DashboardInputError("unable to read selected artifact") from error
    _verify_path_identity(path, root, expected)
    return data


@lru_cache(maxsize=1)
def _canary_bytes() -> bytes:
    return load_canary().encode("utf-8")


def _encoded_json(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as error:
        raise DashboardInputError("dashboard projection is not valid JSON") from error


def encode_safe_projection(value: object) -> bytes:
    encoded = _encoded_json(value)
    if _canary_bytes() in encoded:
        raise DashboardInputError("dashboard projection contains the raw lab canary")
    return encoded


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError as error:
        raise DashboardInputError("unable to inspect selected artifact") from error
    return bool(attributes & 0x400)


def _resolve_artifact(root: Path, entry: DashboardManifestEntry) -> Path:
    candidate = root.joinpath(*entry.path.split("/"))
    current = root
    for part in entry.path.split("/"):
        current = current / part
        if current.is_symlink() or _is_reparse_point(current):
            raise DashboardInputError("artifact path crosses a link or reparse point")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise DashboardInputError("artifact path escapes the manifest directory") from error
    if not resolved.is_file():
        raise DashboardInputError("selected artifact is not a regular file")
    return resolved


def safe_event(event: Event) -> dict[str, object]:
    allowed = _SAFE_PAYLOAD_FIELDS.get(event.event_type, frozenset())
    payload = {key: event.payload[key] for key in sorted(allowed) if key in event.payload}
    return {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "run_id": event.run_id,
        "trace_id": event.trace_id,
        "sequence": event.sequence,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source_component": event.source_component,
        "tool_call_id": event.tool_call_id,
        "payload": payload,
    }


def _safe_report(report: BaseModel) -> dict[str, object]:
    data = report.model_dump(mode="json")
    if isinstance(report, Report):
        data["timeline"] = [safe_event(event) for event in report.timeline]
    return data


def _source_record(entry: DashboardManifestEntry, evidence: ReplayEvidence) -> CatalogRecord:
    snapshot = validate_snapshot(evidence.events, evidence.source_status)
    fingerprint = fingerprint_snapshot(snapshot)
    started = next(event for event in snapshot.events if event.event_type == "run.started")
    terminal = snapshot.events[-1]
    data: dict[str, object] = {
        "id": entry.id,
        "run_id": snapshot.run_id,
        "trace_ids": sorted({event.trace_id for event in snapshot.events}),
        "status": evidence.source_status.value,
        "scenario_id": started.payload.get("scenario_id", "unknown"),
        "profile": started.payload.get("profile", "unknown"),
        "outcome": terminal.payload.get("outcome", "unknown"),
        "event_count": len(snapshot.events),
        "evidence_cutoff_sequence": snapshot.evidence_cutoff_sequence,
        "snapshot_fingerprint": fingerprint,
    }
    record = CatalogRecord(
        CatalogSummary(
            id=entry.id,
            kind=entry.kind,
            provenance=Provenance.VERIFIED,
            title=f"Run {snapshot.run_id}",
            status=evidence.source_status.value,
        ),
        data,
        snapshot.events,
        fingerprint,
    )
    encode_safe_projection(record.data)
    for event in record.events:
        encode_safe_projection(safe_event(event))
    return record


def _references(report: InvestigationReport) -> tuple[EvidenceReference, ...]:
    references: list[EvidenceReference] = []
    for alert in report.derived_alerts:
        references.extend(alert.evidence)
    for incident in report.incidents:
        references.extend(reference for alert in incident.alerts for reference in alert.evidence)
        references.extend(incident.evidence)
        references.extend(reference for stage in incident.stages for reference in stage.evidence)
        references.extend(incident.outcome.evidence)
        references.extend(entry.evidence for entry in incident.timeline)
    return tuple(references)


def _verify_investigation(report: InvestigationReport, source: CatalogRecord) -> None:
    cutoff_events = [
        event for event in source.events if event.sequence <= report.evidence_cutoff_sequence
    ]
    snapshot = validate_snapshot(cutoff_events, report.source_status)
    fingerprint = fingerprint_snapshot(snapshot)
    if report.source_run_id != snapshot.run_id or report.snapshot_fingerprint != fingerprint:
        raise DashboardInputError("investigation does not match its selected evidence source")
    indexed = {event.event_id: event for event in snapshot.events}
    if any(
        reference.snapshot_fingerprint != fingerprint
        or reference.run_id != snapshot.run_id
        or reference.event_id not in indexed
        or reference.sequence != indexed[reference.event_id].sequence
        or reference.trace_id != indexed[reference.event_id].trace_id
        for reference in _references(report)
    ):
        raise DashboardInputError("investigation contains an unresolved evidence reference")
    top_level_alerts = {alert.stable_key: alert for alert in report.derived_alerts}
    if any(
        top_level_alerts.get(alert.stable_key) != alert
        for incident in report.incidents
        for alert in incident.alerts
    ):
        raise DashboardInputError("investigation contains altered nested alert facts")
    direct_ids = {
        incident.stable_key: {
            reference.event_id for alert in incident.alerts for reference in alert.evidence
        }
        for incident in report.incidents
    }
    derived_types = {
        "detection.match",
        "detection.no_match",
        "alert.created",
        "incident.created",
        "report.created",
    }
    for incident in report.incidents:
        for item in incident.timeline:
            event = indexed[item.evidence.event_id]
            if (
                item.timestamp != event.timestamp
                or item.event_type != event.event_type
                or item.source_component != event.source_component
                or item.direct_match_evidence != (event.event_id in direct_ids[incident.stable_key])
                or item.historical_derived_event != (event.event_type in derived_types)
            ):
                raise DashboardInputError("investigation timeline metadata was altered")


def _verify_run_report(report: Report, source: CatalogRecord) -> None:
    if report.run_id != source.data["run_id"]:
        raise DashboardInputError("run report does not match its selected evidence source")
    timeline = tuple(
        event for event in source.events if event.sequence <= report.evidence_cutoff_sequence
    )
    if report.timeline != timeline or not timeline:
        raise DashboardInputError("run report timeline does not exactly match selected evidence")
    started = timeline[0]
    if started.event_type != "run.started" or report.trace_id != started.trace_id:
        raise DashboardInputError("run report identity does not match selected evidence")
    scenario_id = started.payload.get("scenario_id")
    profile = started.payload.get("profile")
    if not isinstance(scenario_id, str) or profile != report.policy_profile.value:
        raise DashboardInputError("run report profile does not match selected evidence")
    try:
        scenario = load_scenario(scenario_id)
    except (OSError, ValidationError, ValueError) as error:
        raise DashboardInputError("run report references an unsupported scenario") from error
    detection = CorrelationDetector().evaluate(list(timeline))
    alert = next((event for event in timeline if event.event_type == "alert.created"), None)
    incident = next((event for event in timeline if event.event_type == "incident.created"), None)
    if detection.detected:
        if alert is None or incident is None:
            raise DashboardInputError("run report detection lacks recorded alert linkage")
        detection = detection.model_copy(
            update={
                "alert_id": alert.payload.get("alert_id"),
                "incident_id": incident.payload.get("incident_id"),
            }
        )
    expected = build_report(
        scenario,
        report.run_id,
        report.trace_id,
        list(timeline),
        detection,
        report.policy_profile,
    )
    if report != expected:
        raise DashboardInputError("run report contents do not match selected evidence")


class DashboardCatalog:
    """An immutable in-memory snapshot of explicitly selected artifacts."""

    def __init__(self, records: tuple[CatalogRecord, ...]) -> None:
        self._records = {record.summary.id: record for record in records}

    @property
    def records(self) -> tuple[CatalogRecord, ...]:
        return tuple(self._records.values())

    def get(self, item_id: str) -> CatalogRecord | None:
        return self._records.get(item_id)

    def by_kind(self, *kinds: ArtifactKind) -> tuple[CatalogRecord, ...]:
        accepted = set(kinds)
        return tuple(record for record in self.records if record.summary.kind in accepted)

    @classmethod
    def load(cls, manifest_path: Path) -> DashboardCatalog:
        started_at = monotonic()

        def check_deadline() -> None:
            if monotonic() - started_at > MAX_DASHBOARD_STARTUP_SECONDS:
                raise DashboardResourceLimitExceeded("dashboard startup exceeds fixed deadline")

        try:
            manifest_path = manifest_path.resolve(strict=True)
            manifest_identity = _identity(manifest_path)
            manifest_size = manifest_identity.size
        except OSError as error:
            raise DashboardInputError("dashboard manifest does not exist") from error
        if manifest_size > MAX_DASHBOARD_MANIFEST_BYTES:
            raise DashboardResourceLimitExceeded("dashboard manifest exceeds fixed limit")
        manifest_root = manifest_path.parent
        try:
            manifest_data = _guarded_read(
                manifest_path, manifest_root, manifest_identity, MAX_DASHBOARD_MANIFEST_BYTES
            )
            manifest = _validate_json_model(DashboardManifest, manifest_data)
        except (OSError, ValidationError) as error:
            raise DashboardInputError("dashboard manifest failed validation") from error
        check_deadline()
        sources = sum(entry.kind is ArtifactKind.EVENT_SOURCE for entry in manifest.entries)
        if sources > MAX_DASHBOARD_RUNS:
            raise DashboardResourceLimitExceeded("dashboard run count exceeds fixed limit")

        selected: dict[str, tuple[DashboardManifestEntry, Path, _FileIdentity]] = {}
        total_bytes = 0
        for entry in manifest.entries:
            path = _resolve_artifact(manifest_root, entry)
            identity = _identity(path)
            size = identity.size
            limit = MAX_RULE_BYTES if entry.kind is ArtifactKind.RULE else MAX_REPORT_BYTES
            if entry.kind is not ArtifactKind.EVENT_SOURCE and size > limit:
                raise DashboardResourceLimitExceeded("selected artifact exceeds its fixed limit")
            total_bytes += size
            if total_bytes > MAX_DASHBOARD_INPUT_BYTES:
                raise DashboardResourceLimitExceeded("selected artifacts exceed aggregate limit")
            selected[entry.id] = (entry, path, identity)
            check_deadline()

        records: dict[str, CatalogRecord] = {}
        event_count = 0
        projection_bytes = 0
        for entry in manifest.entries:
            if entry.kind is not ArtifactKind.EVENT_SOURCE:
                continue
            path, identity = selected[entry.id][1:]
            assert entry.run_id is not None
            _verify_path_identity(path, manifest_root, identity)
            evidence = read_replay_evidence(path, entry.run_id)
            _verify_path_identity(path, manifest_root, identity)
            event_count += len(evidence.events)
            if event_count > MAX_DASHBOARD_EVENTS:
                raise DashboardResourceLimitExceeded("dashboard event count exceeds fixed limit")
            record = _source_record(entry, evidence)
            projection_bytes += len(encode_safe_projection(record.data)) + sum(
                len(_encoded_json(event.model_dump(mode="json"))) for event in record.events
            )
            if projection_bytes > MAX_DASHBOARD_PROJECTION_BYTES:
                raise DashboardResourceLimitExceeded("dashboard projections exceed fixed limit")
            records[entry.id] = record
            check_deadline()
        for entry in manifest.entries:
            if entry.kind is ArtifactKind.EVENT_SOURCE:
                continue
            path, identity = selected[entry.id][1:]
            limit = MAX_RULE_BYTES if entry.kind is ArtifactKind.RULE else MAX_REPORT_BYTES
            encoded_report = _guarded_read(path, manifest_root, identity, limit)
            try:
                report = _validate_json_model(_REPORT_MODELS[entry.kind], encoded_report)
            except ValidationError as error:
                raise DashboardInputError("selected report failed schema validation") from error
            provenance = Provenance.REPORT_ONLY
            if entry.source_id is not None:
                source = records[entry.source_id]
                if isinstance(report, InvestigationReport):
                    _verify_investigation(report, source)
                elif isinstance(report, Report):
                    _verify_run_report(report, source)
                else:
                    raise DashboardInputError("this artifact kind cannot verify against a source")
                provenance = Provenance.VERIFIED
            data = _safe_report(report)
            if entry.source_id is not None:
                data["catalog_source_id"] = entry.source_id
            display_identity = str(
                data.get("run_id")
                or data.get("investigation_id")
                or data.get("evaluation_id")
                or data.get("comparison_id")
                or data.get("replay_id")
                or data.get("rule_id")
                or entry.id
            )
            status = str(data.get("status", "available"))
            encoded = encode_safe_projection(data)
            projection_bytes += len(encoded)
            if projection_bytes > MAX_DASHBOARD_PROJECTION_BYTES:
                raise DashboardResourceLimitExceeded("dashboard projections exceed fixed limit")
            records[entry.id] = CatalogRecord(
                CatalogSummary(
                    id=entry.id,
                    kind=entry.kind,
                    provenance=provenance,
                    title=f"{entry.kind.value.replace('_', ' ').title()} {display_identity}",
                    status=status,
                ),
                data,
            )
            check_deadline()
        return cls(tuple(records[entry.id] for entry in manifest.entries))
