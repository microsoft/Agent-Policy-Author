# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal, cast

from policy_authoring.discovery.contracts import (
    BaseDiscoveryAdapter,
    DiscoveryContext,
    DiscoveryContribution,
)
from policy_authoring.discovery.risk import risk_for_tool
from policy_authoring.domain.models import (
    ContextAttribute,
    ControlObservation,
    DiscoveryEvidence,
    SourceSpan,
    ToolDefinition,
    ToolIdentity,
    ToolProvenance,
)

_TOOL_DECORATORS = {
    "tool",
    "function_tool",
    "kernel_function",
    "ai_function",
}


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


def _call_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _span(path: str, node: ast.AST) -> SourceSpan:
    end_column = getattr(node, "end_col_offset", None)
    return SourceSpan(
        path=path,
        start_line=getattr(node, "lineno", 1),
        start_column=getattr(node, "col_offset", 0) + 1,
        end_line=getattr(node, "end_lineno", None),
        end_column=(
            end_column + 1 if isinstance(end_column, int) else None
        ),
    )


def _identity(
    name: str,
    relative: str,
    qualified_name: str,
    framework: str,
) -> ToolIdentity:
    return ToolIdentity(
        canonical_id=name,
        declared_name=name,
        language="python",
        framework=framework,
        namespace=relative,
        qualified_name=qualified_name,
    )


def _provenance(
    kind: Literal["constructor", "decorator"],
    span: SourceSpan,
    framework: str,
    confidence: float,
) -> list[ToolProvenance]:
    return [
        ToolProvenance(
            source_kind=kind,
            adapter_id="python",
            confidence=confidence,
            language="python",
            framework=framework,
            span=span,
        )
    ]


def _decorated_tools(
    path: Path,
    context: DiscoveryContext,
    tree: ast.Module,
) -> DiscoveryContribution:
    contribution = DiscoveryContribution()
    relative = context.relative(path)
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = {_call_name(item) for item in node.decorator_list}
        matched = decorators.intersection(_TOOL_DECORATORS)
        if not matched:
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
        source_span = _span(relative, node)
        decorator = sorted(matched)[0]
        contribution.tools.append(
            ToolDefinition(
                name=node.name,
                description=description.splitlines()[0] if description else "",
                risk=risk_for_tool(node.name, description),  # type: ignore[arg-type]
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": properties,
                    "required": required,
                },
                mutates_state=None,
                handler=node.name,
                source_path=relative,
                source_line=node.lineno,
                source_span=source_span,
                identity=_identity(node.name, relative, node.name, decorator),
                provenance=_provenance(
                    "decorator",
                    source_span,
                    decorator,
                    0.95,
                ),
                metadata_source="decorator",
            )
        )
        contribution.evidence.append(
            DiscoveryEvidence(
                kind="source",
                path=relative,
                detail=(
                    f"Discovered @{decorator} tool {node.name} "
                    f"at line {node.lineno}"
                ),
                confidence=0.95,
                adapter_id="python",
                span=source_span,
            )
        )
    return contribution


def _call_argument(call: ast.Call, index: int, name: str) -> ast.expr | None:
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
    if not isinstance(node, ast.Call) or _call_name(node.func) != "schema":
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
    context: DiscoveryContext,
    tree: ast.Module,
) -> DiscoveryContribution:
    contribution = DiscoveryContribution()
    relative = context.relative(path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        constructor = _call_name(node.func)
        if constructor not in {"ToolSpec", "ToolDefinition"}:
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
            else risk_for_tool(name, str(description or ""))
        )
        source_span = _span(relative, node)
        qualified_name = handler or name
        contribution.tools.append(
            ToolDefinition(
                name=name,
                description=str(description or ""),
                risk=risk,  # type: ignore[arg-type]
                input_schema=_schema_from_call(schema_node),
                mutates_state=mutates_state,
                requires_approval=requires_approval,
                domain=str(domain) if isinstance(domain, str) else None,
                handler=handler,
                source_path=relative,
                source_line=node.lineno,
                source_span=source_span,
                identity=_identity(
                    name,
                    relative,
                    qualified_name,
                    constructor,
                ),
                provenance=_provenance(
                    "constructor",
                    source_span,
                    constructor,
                    1.0,
                ),
                metadata_source="constructor",
            )
        )
        contribution.evidence.append(
            DiscoveryEvidence(
                kind="source",
                path=relative,
                detail=(
                    f"Discovered constructor-registered tool {name} "
                    f"at line {node.lineno}"
                ),
                confidence=1.0,
                adapter_id="python",
                span=source_span,
            )
        )
    return contribution


class PythonDiscoveryAdapter(BaseDiscoveryAdapter):
    id = "python"
    suffixes = frozenset({".py"})

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            return DiscoveryContribution()
        contribution = _decorated_tools(path, context, tree)
        contribution.extend(_constructor_tools(path, context, tree))
        return contribution

    def finalize(
        self,
        files: list[Path],
        tools: list[ToolDefinition],
        traces: list[Any],
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
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
                        if not isinstance(item, ast.Call):
                            continue
                        called = _call_name(item.func)
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
            relative = context.relative(path)
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

        contribution = DiscoveryContribution(
            context_attributes=sorted(
                context_attributes.values(),
                key=lambda item: item.path,
            )
        )
        for tool in tools:
            if tool.handler is None or (
                tool.identity is not None
                and tool.identity.language not in {None, "python"}
            ):
                continue
            handler_key = (
                f"{tool.source_path}::{tool.handler}"
                if tool.source_path is not None
                else tool.handler
            )
            calls = reachable(handler_key)
            call_names = {
                item.rsplit(".", 1)[-1].split("::")[-1] for item in calls
            }
            source_path, line = function_paths.get(
                handler_key,
                (tool.source_path or "", tool.source_line or 1),
            )
            detected: list[tuple[str, str, float]] = (
                [
                    (
                        "operation_binding",
                        (
                            "Tool execution is bound to the host-provided "
                            "operation context."
                        ),
                        0.9,
                    )
                ]
                if tool.mutates_state and "get_incident" in call_names
                else []
            )
            for call_name, kind, detail, confidence in (
                (
                    "mutate",
                    "mutation_boundary",
                    "Mutating execution flows through a shared mutation boundary.",
                    0.95,
                ),
                (
                    "check_version",
                    "version_check",
                    (
                        "The reachable mutation path checks the expected "
                        "state version."
                    ),
                    0.95,
                ),
                (
                    "execute_idempotent",
                    "idempotency",
                    "The reachable mutation path enforces an idempotency key.",
                    0.95,
                ),
                (
                    "check_approval",
                    "approval_binding",
                    (
                        "The reachable handler validates operation-bound "
                        "approval state."
                    ),
                    0.95,
                ),
                (
                    "record_mutation",
                    "audit",
                    "The reachable mutation path records the state change.",
                    0.9,
                ),
            ):
                if call_name in call_names:
                    detected.append((kind, detail, confidence))
            for kind, detail, confidence in detected:
                contribution.controls.append(
                    ControlObservation(
                        kind=kind,  # type: ignore[arg-type]
                        target_tool=tool.name,
                        detail=detail,
                        path=source_path,
                        line=line,
                        confidence=confidence,
                    )
                )
                contribution.evidence.append(
                    DiscoveryEvidence(
                        kind="control",
                        path=source_path,
                        detail=f"{tool.name}: {detail}",
                        confidence=confidence,
                        adapter_id=self.id,
                    )
                )
        return contribution
