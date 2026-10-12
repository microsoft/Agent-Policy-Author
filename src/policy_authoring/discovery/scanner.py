# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policy_authoring.discovery.contracts import (
    DiscoveryAdapterRegistry,
    DiscoveryContext,
    DiscoveryContribution,
    DiscoveryLimits,
)
from policy_authoring.discovery.registry import default_discovery_registry
from policy_authoring.domain.models import (
    ContextAttribute,
    ContextContract,
    DiscoveryProvenance,
    DiscoveryQuestion,
    DiscoveryReport,
    DiscoverySummary,
    ProjectDefinition,
    ToolDefinition,
)
from policy_authoring.recommendation.service import propose_project_policies

_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".data",
    ".artifacts",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".policy-authoring",
    ".agent-policy",
    ".action-control",
    "generated",
}

_DEFAULT_REGISTRY = default_discovery_registry()
SUPPORTED_DISCOVERY_SUFFIXES = _DEFAULT_REGISTRY.supported_suffixes


@dataclass
class _ScanState:
    files_scanned: int = 0
    bytes_scanned: int = 0


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if len(normalized) < 2:
        normalized = f"project-{normalized or 'agent'}"
    return normalized[:64]


def _is_beneath(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def _resolve_source(
    path: Path,
    allowed_roots: tuple[Path, ...],
) -> tuple[Path, Path | None]:
    source = path.resolve(strict=True)
    root = source if source.is_dir() else source.parent
    selected_file = source if source.is_file() else None
    normalized_roots = tuple(item.resolve(strict=True) for item in allowed_roots)
    if normalized_roots and not _is_beneath(source, normalized_roots):
        allowed = ", ".join(str(item) for item in normalized_roots)
        raise ValueError(f"discovery path is outside allowed roots: {allowed}")
    return root, selected_file


def _bounded_files(
    root: Path,
    limits: DiscoveryLimits,
    state: _ScanState,
    supported_suffixes: frozenset[str],
    selected_file: Path | None = None,
) -> list[Path]:
    files: list[Path] = []
    candidates = [selected_file] if selected_file is not None else root.rglob("*")
    for path in sorted(candidates):
        relative = path.relative_to(root)
        if any(part in _IGNORED_DIRECTORIES for part in relative.parts):
            continue
        if (
            selected_file is None
            and path.name in {"project.yaml", "project.yml", "project.json"}
            and path.parent != root
        ):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in supported_suffixes:
            continue
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            continue
        state.files_scanned += 1
        state.bytes_scanned += size
        if state.files_scanned > limits.max_files:
            raise ValueError(f"discovery exceeded {limits.max_files} files")
        if state.bytes_scanned > limits.max_total_bytes:
            raise ValueError(f"discovery exceeded {limits.max_total_bytes} bytes")
        files.append(path)
    return files


def _identity_key(tool: ToolDefinition) -> str:
    if tool.identity is not None and tool.identity.canonical_id:
        return tool.identity.canonical_id
    return tool.name


def _merge_provenance(
    preferred: ToolDefinition,
    alternate: ToolDefinition,
) -> list[Any] | None:
    values = [*(preferred.provenance or []), *(alternate.provenance or [])]
    if not values:
        return None
    unique: dict[str, Any] = {}
    for item in values:
        key = item.model_dump_json(exclude_none=True)
        unique[key] = item
    return [unique[key] for key in sorted(unique)]


def _merge_tools(
    tools: list[ToolDefinition],
) -> tuple[list[ToolDefinition], list[str]]:
    priority = {
        "heuristic": 0,
        "decorator": 1,
        "openapi": 2,
        "manifest": 3,
        "constructor": 4,
        "runtime_manifest": 5,
        "project": 6,
    }
    merged: dict[str, ToolDefinition] = {}
    for tool in tools:
        key = _identity_key(tool)
        existing = merged.get(key)
        if existing is None:
            merged[key] = tool
            continue
        preferred, alternate = (
            (tool, existing)
            if priority[tool.metadata_source] >= priority[existing.metadata_source]
            else (existing, tool)
        )
        payload = preferred.model_dump()
        for field in (
            "mutates_state",
            "requires_approval",
            "domain",
            "handler",
            "identity",
            "source_span",
        ):
            if payload[field] is None:
                payload[field] = getattr(alternate, field)
        payload["provenance"] = _merge_provenance(preferred, alternate)
        if payload["source_path"] is None:
            payload["source_path"] = alternate.source_path
            payload["source_line"] = alternate.source_line
        preferred_properties = preferred.input_schema.get("properties", {})
        alternate_properties = alternate.input_schema.get("properties", {})
        if len(alternate_properties) > len(preferred_properties):
            payload["input_schema"] = alternate.input_schema
        if payload["mutates_state"] is True:
            payload["risk"] = (
                "consequential-write"
                if payload["requires_approval"] is True
                else "write"
            )
        elif payload["mutates_state"] is False:
            payload["risk"] = "read"
        elif payload["risk"] == "unknown" and alternate.risk != "unknown":
            payload["risk"] = alternate.risk
        merged[key] = ToolDefinition.model_validate(payload)

    warnings: list[str] = []
    by_name: dict[str, list[tuple[str, ToolDefinition]]] = defaultdict(list)
    for key, tool in merged.items():
        by_name[tool.name].append((key, tool))
    resolved: list[ToolDefinition] = []
    for name, items in sorted(by_name.items()):
        if len(items) == 1:
            resolved.append(items[0][1])
            continue
        warnings.append(
            f"{name}: multiple distinct tool identities share this declared name"
        )
        for key, tool in sorted(items, key=lambda item: item[0]):
            suffix = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
            resolved.append(tool.model_copy(update={"name": f"{name}--{suffix}"}))
    return sorted(resolved, key=lambda item: item.name), warnings


def _questions(tools: list[ToolDefinition]) -> list[DiscoveryQuestion]:
    questions: list[DiscoveryQuestion] = []
    for tool in tools:
        if tool.risk == "unknown":
            questions.append(
                DiscoveryQuestion(
                    id=f"classify-{_slug(tool.name)}",
                    title=f"Classify {tool.name}",
                    detail=(
                        "Static discovery could not determine whether this tool "
                        "reads state or performs a consequential action."
                    ),
                    subject=tool.name,
                    options=["read", "write", "consequential-write"],
                )
            )
    return questions


def _summary(
    project: ProjectDefinition,
    *,
    files_scanned: int,
    bytes_scanned: int,
    questions: list[DiscoveryQuestion],
) -> DiscoverySummary:
    return DiscoverySummary(
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
        tools_discovered=len(project.tools),
        consequential_tools=sum(
            item.risk == "consequential-write" for item in project.tools
        ),
        mutating_tools=sum(
            item.mutates_state is True
            or item.risk in {"write", "consequential-write"}
            for item in project.tools
        ),
        approval_required_tools=sum(
            item.requires_approval is True for item in project.tools
        ),
        traces_imported=len(project.traces),
        context_attributes=len(project.context.attributes),
        controls_observed=len(project.controls),
        unresolved_questions=len(questions),
    )


def _explicit_project(
    files: list[Path],
    context: DiscoveryContext,
    registry: DiscoveryAdapterRegistry,
    state: _ScanState,
) -> DiscoveryReport | None:
    for path in files:
        for adapter in registry.project_adapters():
            if not adapter.supports(path, context):
                continue
            contribution = adapter.discover(path, context)
            if contribution.project is None:
                continue
            project = contribution.project
            questions = _questions(project.tools)
            return DiscoveryReport(
                root=str(context.root),
                project=project,
                provenance=DiscoveryProvenance(
                    mode="explicit_project",
                    selected_source=(
                        context.relative(context.selected_file)
                        if context.selected_file is not None
                        else None
                    ),
                    project_definition=context.relative(path),
                    ignored_directories=sorted(_IGNORED_DIRECTORIES),
                    adapters=[adapter.id],
                ),
                summary=_summary(
                    project,
                    files_scanned=state.files_scanned,
                    bytes_scanned=state.bytes_scanned,
                    questions=questions,
                ),
                evidence=contribution.evidence,
                questions=questions,
                proposals=propose_project_policies(project),
                warnings=contribution.warnings,
            )
    return None


def discover_project(
    path: Path,
    *,
    allowed_roots: tuple[Path, ...] = (),
    limits: DiscoveryLimits | None = None,
    registry: DiscoveryAdapterRegistry | None = None,
) -> DiscoveryReport:
    active_limits = limits or DiscoveryLimits()
    active_registry = registry or _DEFAULT_REGISTRY
    root, selected_file = _resolve_source(path, allowed_roots)
    context = DiscoveryContext(
        root=root,
        selected_file=selected_file,
        limits=active_limits,
    )
    state = _ScanState()
    files = _bounded_files(
        root,
        active_limits,
        state,
        active_registry.supported_suffixes,
        selected_file,
    )

    explicit = _explicit_project(files, context, active_registry, state)
    if explicit is not None:
        return explicit

    aggregate = DiscoveryContribution()
    used_adapters: set[str] = set()
    for file_path in files:
        for adapter in active_registry.file_adapters(file_path, context):
            contribution = adapter.discover(file_path, context)
            if any(
                (
                    contribution.tools,
                    contribution.traces,
                    contribution.context_attributes,
                    contribution.controls,
                    contribution.evidence,
                    contribution.warnings,
                )
            ):
                used_adapters.add(adapter.id)
            aggregate.extend(contribution)
            if len(aggregate.traces) > active_limits.max_traces:
                aggregate.traces = aggregate.traces[: active_limits.max_traces]

    tools, identity_warnings = _merge_tools(aggregate.tools)
    aggregate.warnings.extend(identity_warnings)
    for adapter in active_registry.adapters:
        contribution = adapter.finalize(
            files,
            tools,
            aggregate.traces,
            context,
        )
        if any(
            (
                contribution.context_attributes,
                contribution.controls,
                contribution.evidence,
                contribution.warnings,
            )
        ):
            used_adapters.add(adapter.id)
        aggregate.extend(contribution)

    context_by_path = {
        item.path: item for item in aggregate.context_attributes
    }
    if any(tool.requires_approval is True for tool in tools):
        context_by_path.setdefault(
            "workflow.approval.valid",
            ContextAttribute(
                path="workflow.approval.valid",
                type="boolean",
                trust="approval_store",
                source="host.approval_resolver.valid",
            ),
        )
    context_by_path["environment.name"] = ContextAttribute(
        path="environment.name",
        type="string",
        trust="runtime_configuration",
        source="runtime.environment",
    )
    warnings = sorted(set(aggregate.warnings))
    if not aggregate.traces:
        warnings.append(
            "No supported traces were found; state-binding recommendations "
            "will be limited until traces are imported."
        )
    if not tools:
        warnings.append(
            "No supported agent tools were discovered. Control analysis and "
            "policy generation are not applicable to this source."
        )

    project = ProjectDefinition(
        name=_slug(selected_file.stem if selected_file else root.name),
        description=f"Discovered from {selected_file or root}",
        tools=tools,
        context=ContextContract(
            attributes=sorted(
                context_by_path.values(),
                key=lambda item: item.path,
            )
        ),
        traces=aggregate.traces,
        controls=aggregate.controls,
    )
    questions = _questions(tools)
    return DiscoveryReport(
        root=str(root),
        project=project,
        provenance=DiscoveryProvenance(
            mode="source_scan",
            selected_source=(
                context.relative(selected_file)
                if selected_file is not None
                else None
            ),
            ignored_directories=sorted(_IGNORED_DIRECTORIES),
            adapters=sorted(used_adapters),
        ),
        summary=_summary(
            project,
            files_scanned=state.files_scanned,
            bytes_scanned=state.bytes_scanned,
            questions=questions,
        ),
        evidence=aggregate.evidence,
        questions=questions,
        proposals=propose_project_policies(project),
        warnings=warnings,
    )
