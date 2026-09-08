"""Narrow in-process capabilities used by the deterministic lab."""

from __future__ import annotations

from dataclasses import dataclass

from .constants import LAB_SINK_DESTINATION, VIRTUAL_SECRET_PATH


class ResourceDeniedError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SinkObservation:
    canary_id: str
    value_sha256: str
    observed_in: str
    redacted: bool
    matched: bool


class VirtualFileAdapter:
    def __init__(self, canary_value: str) -> None:
        self._resources = {VIRTUAL_SECRET_PATH: canary_value}

    def read(self, path: str) -> str:
        if path != VIRTUAL_SECRET_PATH:
            raise ResourceDeniedError("virtual resource is not available")
        return self._resources[path]


class LabHttpSinkAdapter:
    """Records an attempted transfer without using a network API."""

    def __init__(self, canary_id: str, canary_value: str, value_sha256: str) -> None:
        self._canary_id = canary_id
        self._canary_value = canary_value
        self._value_sha256 = value_sha256
        self._observations: list[SinkObservation] = []

    @property
    def observations(self) -> tuple[SinkObservation, ...]:
        return tuple(self._observations)

    def record(self, destination: str, body: str) -> SinkObservation:
        if destination != LAB_SINK_DESTINATION:
            raise ResourceDeniedError("external destination denied")
        observation = SinkObservation(
            canary_id=self._canary_id,
            value_sha256=self._value_sha256,
            observed_in="http_request_body",
            redacted=True,
            matched=self._canary_value in body,
        )
        self._observations.append(observation)
        return observation

    def clear(self) -> None:
        self._observations.clear()
