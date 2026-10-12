# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import yaml

from policy_authoring.discovery.contracts import (
    BaseDiscoveryAdapter,
    DiscoveryContext,
    DiscoveryContribution,
)
from policy_authoring.discovery.risk import risk_for_tool
from policy_authoring.domain.models import (
    DiscoveryEvidence,
    SourceSpan,
    ToolDefinition,
    ToolIdentity,
    ToolProvenance,
)
from policy_authoring.ingestion.loader import load_project

_FORMAT_SUFFIXES = frozenset({".json", ".yaml", ".yml"})


def _manifest_candidate(path: Path, text: str) -> bool:
    name = path.name.lower()
    return any(
        token in name
        for token in ("openapi", "swagger", "tool", "manifest", "schema", "mcp")
    ) or any(
        marker in text[:4096]
        for marker in ('"openapi"', '"tools"', "openapi:", "tools:")
    )


def _load_mapping(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        value = (
            json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        )
    except json.JSONDecodeError as exc:
        if _manifest_candidate(path, text):
            raise ValueError(
                f"{path}:{exc.lineno}:{exc.colno}: malformed supported "
                f"JSON manifest: {exc.msg}"
            ) from exc
        return None
    except yaml.YAMLError as exc:
        if _manifest_candidate(path, text):
            mark = getattr(exc, "problem_mark", None)
            location = f":{mark.line + 1}:{mark.column + 1}" if mark is not None else ""
            problem = getattr(exc, "problem", None) or str(exc)
            raise ValueError(
                f"{path}{location}: malformed supported YAML manifest: {problem}"
            ) from exc
        return None
    return value if isinstance(value, dict) else None


def _file_span(relative: str) -> SourceSpan:
    return SourceSpan(path=relative, start_line=1, start_column=1)


def _request_schema(operation: dict[str, Any]) -> dict[str, Any]:
    request_body = operation.get("requestBody", {})
    content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
    for media_type in ("application/json", "application/*+json"):
        schema = content.get(media_type, {}).get("schema")
        if isinstance(schema, dict):
            return schema
    properties: dict[str, Any] = {}
    required: list[str] = []
    for parameter in operation.get("parameters", []):
        if not isinstance(parameter, dict) or "name" not in parameter:
            continue
        properties[str(parameter["name"])] = parameter.get(
            "schema",
            {"type": "string"},
        )
        if parameter.get("required") is True:
            required.append(str(parameter["name"]))
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


class ProjectDefinitionAdapter(BaseDiscoveryAdapter):
    id = "project-definition"
    suffixes = _FORMAT_SUFFIXES
    project_adapter = True

    def supports(self, path: Path, context: DiscoveryContext) -> bool:
        return (
            path.name in {"project.yaml", "project.yml", "project.json"}
            and (
                context.selected_file == path
                or path.parent == context.root
            )
        )

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        if not self.supports(path, context):
            return DiscoveryContribution()
        relative = context.relative(path)
        span = _file_span(relative)
        project = load_project(path)
        enriched: list[ToolDefinition] = []
        for tool in project.tools:
            identity = tool.identity or ToolIdentity(
                canonical_id=tool.name,
                declared_name=tool.name,
                qualified_name=tool.handler,
            )
            provenance = tool.provenance or [
                ToolProvenance(
                    source_kind="project",
                    adapter_id=self.id,
                    confidence=1.0,
                    span=span,
                )
            ]
            enriched.append(
                tool.model_copy(
                    update={
                        "identity": identity,
                        "provenance": provenance,
                        "source_span": tool.source_span or span,
                    }
                )
            )
        project = project.model_copy(update={"tools": enriched})
        return DiscoveryContribution(
            project=project,
            evidence=[
                DiscoveryEvidence(
                    kind="manifest",
                    path=relative,
                    detail=(
                        "Imported an existing explicit root policy-authoring "
                        "project definition"
                    ),
                    confidence=1.0,
                    adapter_id=self.id,
                    span=span,
                )
            ],
        )


class OpenApiDiscoveryAdapter(BaseDiscoveryAdapter):
    id = "openapi"
    suffixes = _FORMAT_SUFFIXES

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        document = _load_mapping(path)
        if not document or "openapi" not in document:
            return DiscoveryContribution()
        relative = context.relative(path)
        span = _file_span(relative)
        contribution = DiscoveryContribution()
        for route, operations in document.get("paths", {}).items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method.lower() not in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                } or not isinstance(operation, dict):
                    continue
                name = str(
                    operation.get("operationId")
                    or f"{method}_{str(route).strip('/').replace('/', '_')}"
                )
                description = str(
                    operation.get("summary") or operation.get("description") or ""
                )
                contribution.tools.append(
                    ToolDefinition(
                        name=name,
                        description=description,
                        risk=risk_for_tool(  # type: ignore[arg-type]
                            name,
                            description,
                            method,
                        ),
                        input_schema=_request_schema(operation),
                        mutates_state=method.lower() not in {
                            "get",
                            "head",
                            "options",
                        },
                        source_path=relative,
                        source_span=span,
                        identity=ToolIdentity(
                            canonical_id=name,
                            declared_name=name,
                            framework="openapi",
                            namespace=relative,
                            qualified_name=f"{method.upper()} {route}",
                        ),
                        provenance=[
                            ToolProvenance(
                                source_kind="openapi",
                                adapter_id=self.id,
                                confidence=1.0,
                                framework="openapi",
                                span=span,
                            )
                        ],
                        metadata_source="openapi",
                    )
                )
                contribution.evidence.append(
                    DiscoveryEvidence(
                        kind="schema",
                        path=relative,
                        detail=(
                            f"Imported OpenAPI operation "
                            f"{method.upper()} {route}"
                        ),
                        confidence=1.0,
                        adapter_id=self.id,
                        span=span,
                    )
                )
        return contribution


def _manifest_source_span(
    candidate: dict[str, Any],
    relative: str,
) -> SourceSpan:
    source = candidate.get("source")
    if not isinstance(source, dict):
        return _file_span(relative)
    return SourceSpan(
        path=str(source.get("path") or relative),
        start_line=(
            int(source["startLine"])
            if isinstance(source.get("startLine"), int)
            else 1
        ),
        start_column=(
            int(source["startColumn"])
            if isinstance(source.get("startColumn"), int)
            else 1
        ),
        end_line=(
            int(source["endLine"])
            if isinstance(source.get("endLine"), int)
            else None
        ),
        end_column=(
            int(source["endColumn"])
            if isinstance(source.get("endColumn"), int)
            else None
        ),
    )


class ToolManifestDiscoveryAdapter(BaseDiscoveryAdapter):
    id = "tool-manifest"
    suffixes = _FORMAT_SUFFIXES

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        document = _load_mapping(path)
        if not document or "openapi" in document:
            return DiscoveryContribution()
        candidates: list[dict[str, Any]] = []
        if isinstance(document.get("tools"), list):
            candidates = [
                item for item in document["tools"] if isinstance(item, dict)
            ]
        elif (
            document.get("type") == "object"
            and isinstance(document.get("properties"), dict)
            and any(token in path.stem.lower() for token in ("tool", "schema"))
        ):
            candidates = [
                {
                    "name": document.get("title") or path.stem,
                    "description": document.get("description", ""),
                    "inputSchema": document,
                }
            ]
        if not candidates:
            return DiscoveryContribution()
        relative = context.relative(path)
        contribution = DiscoveryContribution()
        for candidate in candidates:
            name = candidate.get("name")
            schema = candidate.get("inputSchema") or candidate.get("input_schema")
            if not isinstance(name, str) or not isinstance(schema, dict):
                continue
            description = str(candidate.get("description", ""))
            mutating = candidate.get("mutating")
            if not isinstance(mutating, bool):
                mutating = candidate.get("mutates_state")
            approval = candidate.get("requiresApproval")
            if not isinstance(approval, bool):
                approval = candidate.get("requires_approval")
            explicit_mutating = mutating if isinstance(mutating, bool) else None
            explicit_approval = approval if isinstance(approval, bool) else None
            risk = (
                "consequential-write"
                if explicit_mutating and explicit_approval
                else "write"
                if explicit_mutating
                else "read"
                if explicit_mutating is False
                else risk_for_tool(name, description)
            )
            source_span = _manifest_source_span(candidate, relative)
            language = (
                str(candidate["language"])
                if isinstance(candidate.get("language"), str)
                else None
            )
            framework = (
                str(candidate["framework"])
                if isinstance(candidate.get("framework"), str)
                else None
            )
            handler = (
                str(candidate["handler"])
                if isinstance(candidate.get("handler"), str)
                else None
            )
            canonical_id = (
                str(candidate["id"])
                if isinstance(candidate.get("id"), str)
                else name
            )
            metadata_source: Literal["runtime_manifest", "manifest"] = (
                "runtime_manifest"
                if explicit_mutating is not None or explicit_approval is not None
                else "manifest"
            )
            source = candidate.get("source")
            source_line = (
                int(source["startLine"])
                if isinstance(source, dict)
                and isinstance(source.get("startLine"), int)
                else None
            )
            contribution.tools.append(
                ToolDefinition(
                    name=name,
                    description=description,
                    risk=risk,  # type: ignore[arg-type]
                    input_schema=schema,
                    mutates_state=explicit_mutating,
                    requires_approval=explicit_approval,
                    domain=(
                        str(candidate["domain"])
                        if isinstance(candidate.get("domain"), str)
                        else None
                    ),
                    handler=handler,
                    source_path=source_span.path,
                    source_line=source_line,
                    source_span=source_span,
                    identity=ToolIdentity(
                        canonical_id=canonical_id,
                        declared_name=name,
                        language=language,
                        framework=framework,
                        namespace=(
                            str(candidate["namespace"])
                            if isinstance(candidate.get("namespace"), str)
                            else None
                        ),
                        qualified_name=handler,
                    ),
                    provenance=[
                        ToolProvenance(
                            source_kind=metadata_source,
                            adapter_id=self.id,
                            confidence=1.0 if explicit_mutating is not None else 0.95,
                            language=language,
                            framework=framework,
                            span=source_span,
                        )
                    ],
                    metadata_source=metadata_source,
                )
            )
            contribution.evidence.append(
                DiscoveryEvidence(
                    kind="schema",
                    path=relative,
                    detail=f"Imported JSON Schema tool {name}",
                    confidence=0.95,
                    adapter_id=self.id,
                    span=source_span,
                )
            )
        return contribution
