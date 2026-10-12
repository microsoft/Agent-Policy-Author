# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from policy_authoring.domain.models import (
    AgentTrace,
    ContextAttribute,
    ControlObservation,
    DiscoveryEvidence,
    ProjectDefinition,
    ToolDefinition,
)


@dataclass(frozen=True)
class DiscoveryLimits:
    max_files: int = 1_000
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 20_971_520
    max_traces: int = 500


@dataclass(frozen=True)
class DiscoveryContext:
    root: Path
    selected_file: Path | None
    limits: DiscoveryLimits

    def relative(self, path: Path) -> str:
        return str(path.relative_to(self.root))


@dataclass
class DiscoveryContribution:
    tools: list[ToolDefinition] = field(default_factory=list)
    traces: list[AgentTrace] = field(default_factory=list)
    context_attributes: list[ContextAttribute] = field(default_factory=list)
    controls: list[ControlObservation] = field(default_factory=list)
    evidence: list[DiscoveryEvidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    project: ProjectDefinition | None = None

    def extend(self, other: DiscoveryContribution) -> None:
        self.tools.extend(other.tools)
        self.traces.extend(other.traces)
        self.context_attributes.extend(other.context_attributes)
        self.controls.extend(other.controls)
        self.evidence.extend(other.evidence)
        self.warnings.extend(other.warnings)
        if other.project is not None:
            self.project = other.project


class DiscoveryAdapter(Protocol):
    id: str
    suffixes: frozenset[str]
    project_adapter: bool

    def supports(self, path: Path, context: DiscoveryContext) -> bool: ...

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution: ...

    def finalize(
        self,
        files: list[Path],
        tools: list[ToolDefinition],
        traces: list[AgentTrace],
        context: DiscoveryContext,
    ) -> DiscoveryContribution: ...


class BaseDiscoveryAdapter:
    id = "base"
    suffixes: frozenset[str] = frozenset()
    project_adapter = False

    def supports(self, path: Path, context: DiscoveryContext) -> bool:
        return path.suffix.lower() in self.suffixes

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        return DiscoveryContribution()

    def finalize(
        self,
        files: list[Path],
        tools: list[ToolDefinition],
        traces: list[AgentTrace],
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        return DiscoveryContribution()


class DiscoveryAdapterRegistry:
    def __init__(self, adapters: list[DiscoveryAdapter]) -> None:
        ids = [adapter.id for adapter in adapters]
        if len(ids) != len(set(ids)):
            raise ValueError("discovery adapter ids must be unique")
        self._adapters = tuple(adapters)

    @property
    def adapters(self) -> tuple[DiscoveryAdapter, ...]:
        return self._adapters

    @property
    def supported_suffixes(self) -> frozenset[str]:
        return frozenset(
            suffix
            for adapter in self._adapters
            for suffix in adapter.suffixes
        )

    def project_adapters(self) -> tuple[DiscoveryAdapter, ...]:
        return tuple(
            adapter for adapter in self._adapters if adapter.project_adapter
        )

    def file_adapters(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> tuple[DiscoveryAdapter, ...]:
        return tuple(
            adapter
            for adapter in self._adapters
            if not adapter.project_adapter and adapter.supports(path, context)
        )
