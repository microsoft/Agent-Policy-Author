# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import yaml

from policy_authoring.domain.models import (
    AgentTrace,
    ContextAttribute,
    ContextContract,
    ControlObservation,
    DiscoveryEvidence,
    DiscoveryProvenance,
    DiscoveryQuestion,
    DiscoveryReport,
    DiscoverySummary,
    ProjectDefinition,
    ToolDefinition,
    TraceStep,
)
from policy_authoring.ingestion.loader import load_project
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
SUPPORTED_DISCOVERY_SUFFIXES = frozenset(
    {".py", ".json", ".jsonl", ".yaml", ".yml"}
)
_TOOL_DECORATORS = {
    "tool",
    "function_tool",
    "kernel_function",
    "ai_function",
}
_READ_PREFIXES = ("get", "list", "read", "search", "find", "fetch", "inspect")
_WRITE_TOKENS = {
    "apply",
    "create",
    "delete",
    "deploy",
    "disable",
    "execute",
    "publish",
    "revoke",
    "remove",
    "send",
    "submit",
    "suspend",
    "terminate",
    "transfer",
    "update",
    "write",
}


@dataclass(frozen=True)
class DiscoveryLimits:
    max_files: int = 1_000
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 20_971_520
    max_traces: int = 500


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
        if path.suffix.lower() not in SUPPORTED_DISCOVERY_SUFFIXES:
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


def _annotation_schema(node: ast.expr | None) -> dict[str, Any]:
    if node is None:
        return {}
    name = ""
    if isinstance(node, ast.Name):
        name = node.id
    elif isinstance(node, ast.Attribute):
        name = node.attr
    elif isinstance(node, ast.Subscript):
        name = (
            node.value.id
            if isinstance(node.value, ast.Name)
            else getattr(node.value, "attr", "")
        )
        if name.lower() == "literal":
            values = (
                node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            )
            literals = [item.value for item in values if isinstance(item, ast.Constant)]
            if literals and len(literals) == len(values):
                value_type = type(literals[0])
                if all(type(item) is value_type for item in literals):
                    schema_type = {
                        str: "string",
                        int: "integer",
                        float: "number",
                        bool: "boolean",
                    }.get(value_type)
                    if schema_type is not None:
                        return {"type": schema_type, "enum": literals}
    lowered = name.lower()
    if lowered in {"str", "string"}:
        return {"type": "string"}
    if lowered in {"int", "integer"}:
        return {"type": "integer"}
    if lowered in {"float", "number"}:
        return {"type": "number"}
    if lowered in {"bool", "boolean"}:
        return {"type": "boolean"}
    if lowered in {"list", "sequence", "tuple", "set"}:
        return {"type": "array"}
    if lowered in {"dict", "mapping"}:
        return {"type": "object"}
    return {}


def _decorator_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _risk_for_tool(name: str, description: str, method: str | None = None) -> str:
    if method and method.lower() in {"get", "head", "options"}:
        return "read"
    lowered = re.sub(r"[^a-z0-9]+", " ", f"{name} {description}".lower())
    if name.lower().startswith(_READ_PREFIXES):
        return "read"
    if name.lower().startswith(("prepare", "confirm", "validate")):
        return "write"
    if any(token in lowered.split() for token in _WRITE_TOKENS):
        return "consequential-write"
    if method and method.lower() == "delete":
        return "consequential-write"
    if method and method.lower() in {"post", "put", "patch"}:
        return "write"
    return "unknown"


def _python_tools(
    path: Path,
    root: Path,
) -> tuple[list[ToolDefinition], list[DiscoveryEvidence]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return [], []
    tools: list[ToolDefinition] = []
    evidence: list[DiscoveryEvidence] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = {_decorator_name(item) for item in node.decorator_list}
        if not decorators.intersection(_TOOL_DECORATORS):
            continue
        properties: dict[str, Any] = {}
        required: list[str] = []
        defaults_start = len(node.args.args) - len(node.args.defaults)
        for index, argument in enumerate(node.args.args):
            if argument.arg in {"self", "cls"}:
                continue
            properties[argument.arg] = _annotation_schema(argument.annotation)
            if index < defaults_start:
                required.append(argument.arg)
        description = ast.get_docstring(node) or ""
        tool = ToolDefinition(
            name=node.name,
            description=description.splitlines()[0] if description else "",
            risk=_risk_for_tool(node.name, description),  # type: ignore[arg-type]
            input_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": required,
            },
            mutates_state=None,
            handler=node.name,
            source_path=str(path.relative_to(root)),
            source_line=node.lineno,
            metadata_source="decorator",
        )
        tools.append(tool)
        evidence.append(
            DiscoveryEvidence(
                kind="source",
                path=str(path.relative_to(root)),
                detail=(
                    "Discovered @"
                    f"{sorted(decorators.intersection(_TOOL_DECORATORS))[0]} "
                    f"tool {node.name} at line {node.lineno}"
                ),
                confidence=0.95,
            )
        )
    return tools, evidence


def _call_argument(
    call: ast.Call,
    index: int,
    name: str,
) -> ast.expr | None:
    if index < len(call.args):
        return call.args[index]
    return next(
        (item.value for item in call.keywords if item.arg == name),
        None,
    )


def _literal_value(node: ast.expr | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _schema_from_call(node: ast.expr | None) -> dict[str, Any]:
    literal = _literal_value(node)
    if isinstance(literal, dict):
        return literal
    if not isinstance(node, ast.Call) or _decorator_name(node.func) != "schema":
        return {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
    required = _literal_value(
        next(
            (item.value for item in node.keywords if item.arg == "required"),
            node.args[0] if node.args else None,
        )
    )
    properties: dict[str, Any] = {}
    for keyword in node.keywords:
        if keyword.arg is None or keyword.arg == "required":
            continue
        value = _literal_value(keyword.value)
        if isinstance(value, str):
            properties[keyword.arg] = {"type": value}
    return {
        "type": "object",
        "properties": properties,
        "required": required if isinstance(required, list) else [],
        "additionalProperties": False,
    }


def _constructor_tools(
    path: Path,
    root: Path,
) -> tuple[list[ToolDefinition], list[DiscoveryEvidence]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return [], []
    tools: list[ToolDefinition] = []
    evidence: list[DiscoveryEvidence] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _decorator_name(node.func) not in {"ToolSpec", "ToolDefinition"}:
            continue
        name = _literal_value(_call_argument(node, 0, "name"))
        description = _literal_value(_call_argument(node, 1, "description"))
        domain = _literal_value(_call_argument(node, 2, "domain"))
        mutating = _literal_value(_call_argument(node, 3, "mutating"))
        approval = _literal_value(_call_argument(node, 4, "requires_approval"))
        handler_node = _call_argument(node, 5, "handler")
        schema_node = _call_argument(node, 6, "input_schema")
        if not isinstance(name, str):
            continue
        handler = (
            handler_node.id
            if isinstance(handler_node, ast.Name)
            else handler_node.attr
            if isinstance(handler_node, ast.Attribute)
            else None
        )
        mutates_state = mutating if isinstance(mutating, bool) else None
        requires_approval = approval if isinstance(approval, bool) else None
        risk = (
            "consequential-write"
            if mutates_state and requires_approval
            else "write"
            if mutates_state
            else "read"
            if mutates_state is False
            else _risk_for_tool(name, str(description or ""))
        )
        tools.append(
            ToolDefinition(
                name=name,
                description=str(description or ""),
                risk=risk,  # type: ignore[arg-type]
                input_schema=_schema_from_call(schema_node),
                mutates_state=mutates_state,
                requires_approval=requires_approval,
                domain=str(domain) if isinstance(domain, str) else None,
                handler=handler,
                source_path=str(path.relative_to(root)),
                source_line=node.lineno,
                metadata_source="constructor",
            )
        )
        evidence.append(
            DiscoveryEvidence(
                kind="source",
                path=str(path.relative_to(root)),
                detail=(
                    f"Discovered constructor-registered tool {name} "
                    f"at line {node.lineno}"
                ),
                confidence=1.0,
            )
        )
    return tools, evidence


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


def _openapi_tools(
    path: Path,
    root: Path,
) -> tuple[list[ToolDefinition], list[DiscoveryEvidence]]:
    document = _load_mapping(path)
    if not document or "openapi" not in document:
        return [], []
    tools: list[ToolDefinition] = []
    evidence: list[DiscoveryEvidence] = []
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
            tools.append(
                ToolDefinition(
                    name=name,
                    description=description,
                    risk=_risk_for_tool(name, description, method),  # type: ignore[arg-type]
                    input_schema=_request_schema(operation),
                    mutates_state=method.lower() not in {"get", "head", "options"},
                    source_path=str(path.relative_to(root)),
                    metadata_source="openapi",
                )
            )
            evidence.append(
                DiscoveryEvidence(
                    kind="schema",
                    path=str(path.relative_to(root)),
                    detail=f"Imported OpenAPI operation {method.upper()} {route}",
                    confidence=1.0,
                )
            )
    return tools, evidence


def _json_schema_tools(
    path: Path,
    root: Path,
) -> tuple[list[ToolDefinition], list[DiscoveryEvidence]]:
    document = _load_mapping(path)
    if not document or "openapi" in document:
        return [], []
    candidates: list[dict[str, Any]] = []
    if isinstance(document.get("tools"), list):
        candidates = [item for item in document["tools"] if isinstance(item, dict)]
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
    tools: list[ToolDefinition] = []
    evidence: list[DiscoveryEvidence] = []
    for candidate in candidates:
        name = candidate.get("name")
        schema = candidate.get("inputSchema") or candidate.get("input_schema")
        if not isinstance(name, str) or not isinstance(schema, dict):
            continue
        description = str(candidate.get("description", ""))
        mutating = candidate.get("mutating")
        if not isinstance(mutating, bool):
            mutating = candidate.get("mutates_state")
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
            else _risk_for_tool(name, description)
        )
        tools.append(
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
                handler=(
                    str(candidate["handler"])
                    if isinstance(candidate.get("handler"), str)
                    else None
                ),
                source_path=str(path.relative_to(root)),
                metadata_source=(
                    "runtime_manifest"
                    if explicit_mutating is not None or explicit_approval is not None
                    else "manifest"
                ),
            )
        )
        evidence.append(
            DiscoveryEvidence(
                kind="schema",
                path=str(path.relative_to(root)),
                detail=f"Imported JSON Schema tool {name}",
                confidence=0.95,
            )
        )
    return tools, evidence


def _read_trace_documents(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    values: list[Any]
    if path.suffix.lower() == ".jsonl":
        values = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_number}:{exc.colno}: malformed supported "
                    f"Agent Hooks JSONL trace: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise ValueError(
                    f"{path}:{line_number}: supported Agent Hooks JSONL trace "
                    "records must be JSON objects"
                )
            values.append(value)
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path}:{exc.lineno}:{exc.colno}: malformed supported "
                f"Agent Hooks JSON trace: {exc.msg}"
            ) from exc
        values = parsed if isinstance(parsed, list) else [parsed]
    return [item for item in values if isinstance(item, dict)]


def _agent_hooks_traces(
    path: Path,
    root: Path,
    max_traces: int,
) -> tuple[list[AgentTrace], list[DiscoveryEvidence]]:
    documents = _read_trace_documents(path)
    if not documents or not any(
        str(item.get("spec", "")).startswith("agent-hooks/")
        or "interception_point" in item
        for item in documents
    ):
        return [], []
    sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in documents:
        session = item.get("session", {})
        session_id = (
            session.get("id") if isinstance(session, dict) else item.get("session_id")
        )
        sessions[str(session_id or path.stem)].append(item)
    traces: list[AgentTrace] = []
    for session_id, records in sorted(sessions.items()):
        steps: list[TraceStep] = []
        for record in sorted(records, key=lambda item: int(item.get("sequence", 0))):
            point = record.get("interception_point")
            tool_call = record.get("tool_call", {})
            if point == "pre_tool_call" and isinstance(tool_call, dict):
                steps.append(
                    TraceStep(
                        type="tool_call",
                        tool=str(tool_call.get("name", "unknown_tool")),
                        arguments=tool_call.get("args")
                        if isinstance(tool_call.get("args"), dict)
                        else {},
                    )
                )
            elif point == "post_tool_call" and isinstance(tool_call, dict):
                target = record.get("target")
                result = record.get("tool_result", target)
                steps.append(
                    TraceStep(
                        type="tool_result",
                        tool=str(tool_call.get("name", "unknown_tool")),
                        output=(
                            result if isinstance(result, dict) else {"value": result}
                        ),
                    )
                )
        if steps:
            traces.append(
                AgentTrace(
                    id=f"agent-hooks-{session_id}",
                    steps=steps,
                )
            )
        if len(traces) >= max_traces:
            break
    evidence = (
        [
            DiscoveryEvidence(
                kind="trace",
                path=str(path.relative_to(root)),
                detail=f"Imported {len(traces)} Agent Hooks session trace(s)",
                confidence=1.0,
            )
        ]
        if traces
        else []
    )
    return traces, evidence


def _context_from_traces(traces: list[AgentTrace]) -> list[ContextAttribute]:
    attributes: dict[str, ContextAttribute] = {}
    for trace in traces:
        for step in trace.steps:
            if step.type != "tool_result" or not step.output:
                continue
            if step.tool.startswith("prepare"):
                prefix = "workflow.prepared"
                trust = "workflow_store"
            elif step.tool.startswith("confirm"):
                prefix = "workflow.confirmation"
                trust = "approval_store"
            else:
                continue
            for name, value in step.output.items():
                if isinstance(value, (dict, list)):
                    continue
                value_type = (
                    "boolean"
                    if isinstance(value, bool)
                    else "integer"
                    if isinstance(value, int)
                    else "number"
                    if isinstance(value, float)
                    else "string"
                )
                path = f"{prefix}.{name}"
                attributes[path] = ContextAttribute(
                    path=path,
                    type=value_type,  # type: ignore[arg-type]
                    trust=trust,  # type: ignore[arg-type]
                    source=f"{step.tool}.output.{name}",
                )
    return sorted(attributes.values(), key=lambda item: item.path)


def _python_structure(
    files: list[Path],
    root: Path,
    tools: list[ToolDefinition],
) -> tuple[
    list[ContextAttribute],
    list[ControlObservation],
    list[DiscoveryEvidence],
]:
    function_calls: dict[str, set[str]] = defaultdict(set)
    function_paths: dict[str, tuple[str, int]] = {}
    simple_names: dict[str, set[str]] = defaultdict(set)
    context_attributes: dict[str, ContextAttribute] = {}

    class FunctionCollector(ast.NodeVisitor):
        def __init__(self, relative: str) -> None:
            self.relative = relative
            self.scope: list[str] = []

        def _visit_function(
            self,
            node: ast.FunctionDef | ast.AsyncFunctionDef,
        ) -> None:
            self.scope.append(node.name)
            qualified = f"{self.relative}::{'.'.join(self.scope)}"
            function_paths[qualified] = (self.relative, node.lineno)
            simple_names[node.name].add(qualified)
            local_functions = {
                item.name
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for item in ast.walk(child):
                    if isinstance(item, ast.Call):
                        called = _decorator_name(item.func)
                        if called:
                            function_calls[qualified].add(called)
                        for argument in [
                            *item.args,
                            *(keyword.value for keyword in item.keywords),
                        ]:
                            if (
                                isinstance(argument, ast.Name)
                                and argument.id in local_functions
                            ):
                                function_calls[qualified].add(
                                    f"{qualified}.{argument.id}"
                                )
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.visit(child)
            self.scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(
            self,
            node: ast.AsyncFunctionDef,
        ) -> None:
            self._visit_function(node)

    for path in files:
        if path.suffix.lower() != ".py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        relative = str(path.relative_to(root))
        FunctionCollector(relative).visit(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.lower() in {
                "toolcontext",
                "agentcontext",
                "executioncontext",
                "runtimecontext",
            }:
                for item in node.body:
                    if not isinstance(item, ast.AnnAssign) or not isinstance(
                        item.target,
                        ast.Name,
                    ):
                        continue
                    value_type = _annotation_schema(item.annotation).get(
                        "type",
                        "string",
                    )
                    context_path = f"runtime.tool_context.{item.target.id}"
                    context_attributes[context_path] = ContextAttribute(
                        path=context_path,
                        type=cast(
                            Literal[
                                "string",
                                "number",
                                "integer",
                                "boolean",
                                "object",
                                "array",
                            ],
                            value_type,
                        ),
                        trust="runtime_configuration",
                        source=f"{relative}:{node.name}.{item.target.id}",
                    )

    def reachable(start: str) -> set[str]:
        seen: set[str] = set()
        pending = [start]
        while pending and len(seen) < 256:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            current_file = current.split("::", 1)[0]
            for called in function_calls.get(current, set()):
                if "::" in called:
                    resolved = called
                else:
                    same_file = f"{current_file}::{called}"
                    candidates = simple_names.get(called, set())
                    resolved = (
                        same_file
                        if same_file in function_paths
                        else next(iter(candidates))
                        if len(candidates) == 1
                        else called
                    )
                if resolved not in seen:
                    pending.append(resolved)
        return seen

    observations: list[ControlObservation] = []
    evidence: list[DiscoveryEvidence] = []
    for tool in tools:
        if tool.handler is None:
            continue
        handler_key = (
            f"{tool.source_path}::{tool.handler}"
            if tool.source_path is not None
            else tool.handler
        )
        calls = reachable(handler_key)
        call_names = {item.rsplit(".", 1)[-1].split("::")[-1] for item in calls}
        source_path, line = function_paths.get(
            handler_key,
            (tool.source_path or "", tool.source_line or 1),
        )
        detected: list[tuple[str, str, float]] = (
            [
                (
                    "operation_binding",
                    "Tool execution is bound to the host-provided operation context.",
                    0.9,
                )
            ]
            if tool.mutates_state and "get_incident" in call_names
            else []
        )
        if "mutate" in call_names:
            detected.append(
                (
                    "mutation_boundary",
                    "Mutating execution flows through a shared mutation boundary.",
                    0.95,
                )
            )
        if "check_version" in call_names:
            detected.append(
                (
                    "version_check",
                    "The reachable mutation path checks the expected state version.",
                    0.95,
                )
            )
        if "execute_idempotent" in call_names:
            detected.append(
                (
                    "idempotency",
                    "The reachable mutation path enforces an idempotency key.",
                    0.95,
                )
            )
        if "check_approval" in call_names:
            detected.append(
                (
                    "approval_binding",
                    "The reachable handler validates operation-bound approval state.",
                    0.95,
                )
            )
        if "record_mutation" in call_names:
            detected.append(
                (
                    "audit",
                    "The reachable mutation path records the state change.",
                    0.9,
                )
            )
        for kind, detail, confidence in detected:
            observation = ControlObservation(
                kind=kind,  # type: ignore[arg-type]
                target_tool=tool.name,
                detail=detail,
                path=source_path,
                line=line,
                confidence=confidence,
            )
            observations.append(observation)
            evidence.append(
                DiscoveryEvidence(
                    kind="control",
                    path=source_path,
                    detail=f"{tool.name}: {detail}",
                    confidence=confidence,
                )
            )
    return (
        sorted(context_attributes.values(), key=lambda item: item.path),
        observations,
        evidence,
    )


def _merge_tools(tools: list[ToolDefinition]) -> list[ToolDefinition]:
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
        existing = merged.get(tool.name)
        if existing is None:
            merged[tool.name] = tool
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
        ):
            if payload[field] is None:
                payload[field] = getattr(alternate, field)
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
        merged[tool.name] = ToolDefinition.model_validate(payload)
    return sorted(merged.values(), key=lambda item: item.name)


def _questions(tools: list[ToolDefinition]) -> list[DiscoveryQuestion]:
    questions = []
    for tool in tools:
        if tool.risk == "unknown":
            questions.append(
                DiscoveryQuestion(
                    id=f"classify-{_slug(tool.name)}",
                    title=f"Classify {tool.name}",
                    detail=(
                        "Static discovery could not determine whether this tool "
                        "reads data or causes an external side effect."
                    ),
                    subject=tool.name,
                    options=["read", "write", "consequential-write"],
                    recommended="write",
                )
            )
    return questions


def _existing_project(
    files: list[Path],
    root: Path,
    selected_file: Path | None,
) -> tuple[ProjectDefinition | None, list[DiscoveryEvidence]]:
    candidates = (
        [selected_file]
        if selected_file is not None
        else [root / name for name in ("project.yaml", "project.yml", "project.json")]
    )
    for path in candidates:
        if (
            path is None
            or path not in files
            or path.name not in {"project.yaml", "project.yml", "project.json"}
        ):
            continue
        project = load_project(path)
        return project, [
            DiscoveryEvidence(
                kind="manifest",
                path=str(path.relative_to(root)),
                detail=(
                    "Imported an existing explicit root policy-authoring "
                    "project definition"
                ),
                confidence=1.0,
            )
        ]
    return None, []


def discover_project(
    path: Path,
    *,
    allowed_roots: tuple[Path, ...] = (),
    limits: DiscoveryLimits | None = None,
) -> DiscoveryReport:
    active_limits = limits or DiscoveryLimits()
    root, selected_file = _resolve_source(path, allowed_roots)
    state = _ScanState()
    files = _bounded_files(root, active_limits, state, selected_file)

    existing, existing_evidence = _existing_project(files, root, selected_file)
    if existing is not None:
        questions = _questions(existing.tools)
        proposals = propose_project_policies(existing)
        return DiscoveryReport(
            root=str(root),
            project=existing,
            provenance=DiscoveryProvenance(
                mode="explicit_project",
                selected_source=(
                    str(selected_file.relative_to(root))
                    if selected_file is not None
                    else None
                ),
                project_definition=existing_evidence[0].path,
                ignored_directories=sorted(_IGNORED_DIRECTORIES),
            ),
            summary=DiscoverySummary(
                files_scanned=state.files_scanned,
                bytes_scanned=state.bytes_scanned,
                tools_discovered=len(existing.tools),
                consequential_tools=sum(
                    item.risk == "consequential-write" for item in existing.tools
                ),
                mutating_tools=sum(
                    item.mutates_state is True
                    or item.risk in {"write", "consequential-write"}
                    for item in existing.tools
                ),
                approval_required_tools=sum(
                    item.requires_approval is True for item in existing.tools
                ),
                traces_imported=len(existing.traces),
                context_attributes=len(existing.context.attributes),
                controls_observed=len(existing.controls),
                unresolved_questions=len(questions),
            ),
            evidence=existing_evidence,
            questions=questions,
            proposals=proposals,
        )

    tools: list[ToolDefinition] = []
    traces: list[AgentTrace] = []
    evidence: list[DiscoveryEvidence] = []
    warnings: list[str] = []
    for file_path in files:
        if file_path.suffix.lower() == ".py":
            found, found_evidence = _python_tools(file_path, root)
            tools.extend(found)
            evidence.extend(found_evidence)
            constructed, constructor_evidence = _constructor_tools(
                file_path,
                root,
            )
            tools.extend(constructed)
            evidence.extend(constructor_evidence)
        elif file_path.suffix.lower() in {".yaml", ".yml", ".json"}:
            found, found_evidence = _openapi_tools(file_path, root)
            tools.extend(found)
            evidence.extend(found_evidence)
            schema_tools, schema_evidence = _json_schema_tools(file_path, root)
            tools.extend(schema_tools)
            evidence.extend(schema_evidence)
        if file_path.suffix.lower() in {".json", ".jsonl"} and any(
            token in file_path.name.lower()
            for token in ("trace", "hook", "interception")
        ):
            found_traces, trace_evidence = _agent_hooks_traces(
                file_path,
                root,
                active_limits.max_traces - len(traces),
            )
            traces.extend(found_traces)
            evidence.extend(trace_evidence)

    tools = _merge_tools(tools)
    (
        source_context_attributes,
        control_observations,
        control_evidence,
    ) = _python_structure(files, root, tools)
    evidence.extend(control_evidence)
    context_by_path = {
        item.path: item
        for item in [
            *_context_from_traces(traces),
            *source_context_attributes,
        ]
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
    context_attributes = sorted(
        context_by_path.values(),
        key=lambda item: item.path,
    )
    context_attributes.append(
        ContextAttribute(
            path="environment.name",
            type="string",
            trust="runtime_configuration",
            source="runtime.environment",
        )
    )
    if not traces:
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
        context=ContextContract(attributes=context_attributes),
        traces=traces,
        controls=control_observations,
    )
    questions = _questions(tools)
    proposals = propose_project_policies(project)
    return DiscoveryReport(
        root=str(root),
        project=project,
        provenance=DiscoveryProvenance(
            mode="source_scan",
            selected_source=(
                str(selected_file.relative_to(root))
                if selected_file is not None
                else None
            ),
            ignored_directories=sorted(_IGNORED_DIRECTORIES),
        ),
        summary=DiscoverySummary(
            files_scanned=state.files_scanned,
            bytes_scanned=state.bytes_scanned,
            tools_discovered=len(tools),
            consequential_tools=sum(
                item.risk == "consequential-write" for item in tools
            ),
            mutating_tools=sum(
                item.mutates_state is True
                or item.risk in {"write", "consequential-write"}
                for item in tools
            ),
            approval_required_tools=sum(
                item.requires_approval is True for item in tools
            ),
            traces_imported=len(traces),
            context_attributes=len(context_attributes),
            controls_observed=len(control_observations),
            unresolved_questions=len(questions),
        ),
        evidence=evidence,
        questions=questions,
        proposals=proposals,
        warnings=warnings,
    )
