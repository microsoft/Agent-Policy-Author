# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompilationResult,
    ContextContract,
    ProjectDefinition,
)


@dataclass(frozen=True)
class AdapterCapabilities:
    supported_decisions: tuple[str, ...]
    lowered_decisions: tuple[str, ...]
    supported_default_decisions: tuple[str, ...]
    supported_operators: tuple[str, ...]
    supported_types: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    validation_assurance: str = "native"


class PolicyTargetAdapter(ABC):
    name: str
    capability_version: str = "1"
    capabilities: AdapterCapabilities

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.capability_version}"

    @abstractmethod
    def compile(
        self,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> CompilationResult:
        """Compile canonical policy into target-native artifacts."""

    def trusted_context(self, project: ProjectDefinition) -> ContextContract:
        return ContextContract(
            attributes=[
                item
                for item in project.context.attributes
                if item.trust not in {"model_provided", "untrusted"}
            ]
        )

    def source_targets(
        self,
        policy: CanonicalPolicy,
    ) -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in policy.source_targets]


class AdapterRegistry:
    def __init__(self, adapters: list[PolicyTargetAdapter]) -> None:
        self._adapters = {adapter.name: adapter for adapter in adapters}

    @property
    def names(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, name: str) -> PolicyTargetAdapter:
        try:
            return self._adapters[name]
        except KeyError as error:
            supported = ", ".join(self.names)
            raise ValueError(
                f"unknown target {name!r}; supported targets: {supported}"
            ) from error

    def validate_selection(self, targets: list[str]) -> None:
        selected = set(targets)
        if len(selected) != len(targets):
            raise ValueError("compilation targets must be unique")
        for target in targets:
            adapter = self.get(target)
            missing = sorted(set(adapter.capabilities.dependencies) - selected)
            if missing:
                raise ValueError(
                    f"target {target!r} requires companion target(s): "
                    + ", ".join(missing)
                )

    def order_selection(self, targets: list[str]) -> list[str]:
        self.validate_selection(targets)
        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(target: str) -> None:
            if target in visited:
                return
            if target in visiting:
                raise ValueError(f"target dependency cycle includes {target!r}")
            visiting.add(target)
            adapter = self.get(target)
            for dependency in adapter.capabilities.dependencies:
                visit(dependency)
            visiting.remove(target)
            visited.add(target)
            ordered.append(target)

        for target in targets:
            visit(target)
        return ordered
