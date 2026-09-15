"""Strict Phase 5 dashboard manifest and read projection models."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from .constants import DASHBOARD_SCHEMA_VERSION, MAX_DASHBOARD_ENTRIES
from .models import StrictModel


class ArtifactKind(StrEnum):
    EVENT_SOURCE = "event_source"
    RUN_REPORT = "run_report"
    COMPARISON = "comparison"
    REPLAY = "replay"
    INVESTIGATION = "investigation"
    EVALUATION = "evaluation"
    RULE = "rule"
    RULE_TEST = "rule_test"


class Provenance(StrEnum):
    VERIFIED = "verified_against_source"
    REPORT_ONLY = "report_only"


class DashboardManifestEntry(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    kind: ArtifactKind
    path: str = Field(min_length=1, max_length=512)
    run_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,96}$")
    source_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")

    @field_validator("path")
    @classmethod
    def path_must_be_confined_relative_posix(cls, value: str) -> str:
        windows = PureWindowsPath(value)
        posix = PurePosixPath(value)
        if (
            "\\" in value
            or ":" in value
            or "\x00" in value
            or windows.is_absolute()
            or windows.drive
            or posix.is_absolute()
            or any(part in {"", ".", ".."} for part in posix.parts)
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("artifact path must be a confined relative POSIX path")
        return value

    @model_validator(mode="after")
    def kind_fields_are_consistent(self) -> Self:
        if self.kind is ArtifactKind.EVENT_SOURCE:
            if self.run_id is None or self.source_id is not None:
                raise ValueError("event sources require run_id and cannot reference source_id")
        elif self.run_id is not None:
            raise ValueError("run_id applies only to event sources")
        if self.source_id == self.id:
            raise ValueError("an entry cannot reference itself")
        return self


class DashboardManifest(StrictModel):
    schema_version: Literal["1.0"] = DASHBOARD_SCHEMA_VERSION
    entries: tuple[DashboardManifestEntry, ...] = Field(max_length=MAX_DASHBOARD_ENTRIES)

    @model_validator(mode="after")
    def identities_and_links_are_valid(self) -> Self:
        identities = [entry.id for entry in self.entries]
        if len(identities) != len(set(identities)):
            raise ValueError("dashboard manifest contains duplicate entry IDs")
        by_id = {entry.id: entry for entry in self.entries}
        for entry in self.entries:
            if entry.source_id is not None:
                source = by_id.get(entry.source_id)
                if source is None or source.kind is not ArtifactKind.EVENT_SOURCE:
                    raise ValueError("dashboard source_id must reference an event source")
        return self


class CatalogSummary(StrictModel):
    id: str
    kind: ArtifactKind
    provenance: Provenance
    title: str
    status: str


class Page(StrictModel):
    items: tuple[dict[str, object], ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)


def valid_catalog_id(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is not None
