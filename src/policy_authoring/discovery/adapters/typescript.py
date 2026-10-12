# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

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

_TOOL_DECORATORS = {
    "tool",
    "functionTool",
    "function_tool",
    "kernelFunction",
    "kernel_function",
    "aiFunction",
    "ai_function",
}
_TOOL_FACTORIES = {
    "tool",
    "functionTool",
    "function_tool",
    "defineTool",
    "createTool",
}


def _parser(path: Path) -> Parser:
    capsule = (
        tree_sitter_typescript.language_tsx()
        if path.suffix.lower() == ".tsx"
        else tree_sitter_typescript.language_typescript()
    )
    return Parser(Language(capsule))


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _walk(node: Node) -> Iterable[Node]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _named_children(node: Node) -> Iterable[Node]:
    return (child for child in node.children if child.is_named)


def _span(relative: str, node: Node) -> SourceSpan:
    return SourceSpan(
        path=relative,
        start_line=node.start_point.row + 1,
        start_column=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column + 1,
    )


def _last_identifier(value: str) -> str:
    matches = re.findall(r"[A-Za-z_$][\w$]*", value)
    return matches[-1] if matches else ""


def _decorators(node: Node, source: bytes) -> set[str]:
    values: set[str] = set()
    candidates = list(node.children)
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type == "decorator":
        candidates.append(sibling)
        sibling = sibling.prev_named_sibling
    for child in candidates:
        if child.type == "decorator":
            name = _last_identifier(_text(child, source).split("(", 1)[0])
            if name:
                values.add(name)
    return values


def _split_parameters(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    final = value[start:].strip()
    if final:
        parts.append(final)
    return parts


def _literal(value: str) -> Any:
    stripped = value.strip()
    if stripped in {"true", "false"}:
        return stripped == "true"
    if stripped == "null":
        return None
    if re.fullmatch(r"-?\d+", stripped):
        return int(stripped)
    if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", stripped):
        return float(stripped)
    if (
        len(stripped) >= 2
        and stripped[0] == stripped[-1]
        and stripped[0] in {"'", '"', "`"}
        and "${" not in stripped
    ):
        return stripped[1:-1]
    return None


def _schema_from_type(
    type_text: str | None,
    default_text: str | None,
) -> dict[str, Any]:
    if type_text:
        normalized = type_text.strip()
        union = _split_union(normalized)
        literals = [_literal(item) for item in union]
        if len(union) > 1 and all(item is not None for item in literals):
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
        lowered = normalized.lower().replace(" ", "")
        if lowered in {"string"}:
            return {"type": "string"}
        if lowered in {"number", "bigint"}:
            return {"type": "number"}
        if lowered in {"boolean"}:
            return {"type": "boolean"}
        if lowered.endswith("[]") or lowered.startswith(
            ("array<", "readonlyarray<")
        ):
            return {"type": "array"}
        if lowered in {"object", "record<string,unknown>", "record<string,any>"}:
            return {"type": "object"}
    if default_text:
        stripped = default_text.strip()
        inferred = _literal(stripped)
        if isinstance(inferred, bool):
            return {"type": "boolean"}
        if isinstance(inferred, int):
            return {"type": "integer"}
        if isinstance(inferred, float):
            return {"type": "number"}
        if isinstance(inferred, str):
            return {"type": "string"}
        if stripped.startswith("["):
            return {"type": "array"}
        if stripped.startswith("{"):
            return {"type": "object"}
    return {}


def _split_union(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth = max(0, depth - 1)
        elif character == "|" and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def _parameter_schema(parameters_text: str) -> dict[str, Any]:
    value = parameters_text.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1]
    properties: dict[str, Any] = {}
    required: list[str] = []
    for parameter in _split_parameters(value):
        match = re.match(
            r"^(?:\.\.\.)?(?:public\s+|private\s+|protected\s+|readonly\s+)*"
            r"([A-Za-z_$][\w$]*)(\?)?\s*"
            r"(?::\s*([^=]+?))?\s*(?:=\s*(.+))?$",
            parameter,
            flags=re.DOTALL,
        )
        if match is None:
            continue
        name, optional, type_text, default_text = match.groups()
        properties[name] = _schema_from_type(type_text, default_text)
        if optional is None and default_text is None:
            required.append(name)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


def _description(node: Node, source: bytes) -> str:
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type == "decorator":
        sibling = sibling.prev_named_sibling
    if sibling is not None and sibling.type == "comment":
        comment = _text(sibling, source)
        if comment.startswith("/**"):
            lines = [
                re.sub(r"^\s*\*\s?", "", line).strip()
                for line in comment[3:-2].splitlines()
            ]
            return next(
                (line for line in lines if line and not line.startswith("@")),
                "",
            )
    prefix = source[: node.start_byte].decode("utf-8")
    match = re.search(r"/\*\*(.*?)\*/\s*$", prefix, flags=re.DOTALL)
    if match is None:
        return ""
    lines = [
        re.sub(r"^\s*\*\s?", "", line).strip()
        for line in match.group(1).splitlines()
    ]
    return next((line for line in lines if line and not line.startswith("@")), "")


def _qualified_name(node: Node, source: bytes, name: str) -> str:
    current = node.parent
    while current is not None:
        if current.type in {"class_declaration", "abstract_class_declaration"}:
            class_name = current.child_by_field_name("name")
            if class_name is not None:
                return f"{_text(class_name, source)}.{name}"
        current = current.parent
    return name


def _call_name(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    return _last_identifier(_text(function, source)) if function is not None else ""


def _object_properties(node: Node, source: bytes) -> dict[str, Node]:
    properties: dict[str, Node] = {}
    for child in _named_children(node):
        if child.type not in {
            "pair",
            "method_definition",
            "shorthand_property_identifier",
        }:
            continue
        if child.type == "shorthand_property_identifier":
            properties[_text(child, source)] = child
            continue
        key = child.child_by_field_name("key") or child.child_by_field_name("name")
        value = child.child_by_field_name("value") or child
        if key is not None:
            properties[_text(key, source).strip("'\"")] = value
    return properties


def _jsonish_schema(node: Node | None, source: bytes) -> dict[str, Any]:
    if node is None:
        return {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
    text = _text(node, source)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
    return value if isinstance(value, dict) else {}


def _tool_definition(
    *,
    name: str,
    description: str,
    schema: dict[str, Any],
    handler: str | None,
    framework: str,
    relative: str,
    node: Node,
    mutates_state: bool | None = None,
    requires_approval: bool | None = None,
) -> ToolDefinition:
    source_span = _span(relative, node)
    risk = (
        "consequential-write"
        if mutates_state and requires_approval
        else "write"
        if mutates_state
        else "read"
        if mutates_state is False
        else risk_for_tool(name, description)
    )
    return ToolDefinition(
        name=name,
        description=description,
        risk=risk,  # type: ignore[arg-type]
        input_schema=schema,
        mutates_state=mutates_state,
        requires_approval=requires_approval,
        handler=handler,
        source_path=relative,
        source_line=source_span.start_line,
        source_span=source_span,
        identity=ToolIdentity(
            canonical_id=name,
            declared_name=name,
            language="typescript",
            framework=framework,
            namespace=relative,
            qualified_name=handler,
        ),
        provenance=[
            ToolProvenance(
                source_kind="source",
                adapter_id="typescript",
                confidence=0.95,
                language="typescript",
                framework=framework,
                span=source_span,
            )
        ],
        metadata_source="decorator",
    )


class TypeScriptDiscoveryAdapter(BaseDiscoveryAdapter):
    id = "typescript"
    suffixes = frozenset({".ts", ".tsx", ".js", ".jsx", ".mts", ".cts"})

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        try:
            source = path.read_bytes()
            tree = _parser(path).parse(source)
        except (OSError, UnicodeDecodeError):
            return DiscoveryContribution()
        relative = context.relative(path)
        contribution = DiscoveryContribution()
        if tree.root_node.has_error:
            contribution.warnings.append(
                f"{relative}: TypeScript parser reported syntax errors"
            )
        seen: set[tuple[str, int]] = set()
        for node in _walk(tree.root_node):
            if node.type in {"function_declaration", "method_definition"}:
                matched = _decorators(node, source).intersection(_TOOL_DECORATORS)
                if not matched:
                    continue
                name_node = node.child_by_field_name("name")
                parameters = node.child_by_field_name("parameters")
                if name_node is None or parameters is None:
                    continue
                name = _text(name_node, source)
                framework = sorted(matched)[0]
                key = (name, node.start_byte)
                if key in seen:
                    continue
                seen.add(key)
                handler = _qualified_name(node, source, name)
                tool = _tool_definition(
                    name=name,
                    description=_description(node, source),
                    schema=_parameter_schema(_text(parameters, source)),
                    handler=handler,
                    framework=framework,
                    relative=relative,
                    node=node,
                )
                contribution.tools.append(tool)
                contribution.evidence.append(
                    DiscoveryEvidence(
                        kind="source",
                        path=relative,
                        detail=(
                            f"Discovered @{framework} TypeScript tool "
                            f"{name} at line {tool.source_line}"
                        ),
                        confidence=0.95,
                        adapter_id=self.id,
                        span=tool.source_span,
                    )
                )
            elif node.type == "call_expression":
                framework = _call_name(node, source)
                if framework not in _TOOL_FACTORIES:
                    continue
                if node.parent is not None and node.parent.type == "decorator":
                    continue
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    continue
                object_node = next(
                    (
                        child
                        for child in _named_children(arguments)
                        if child.type == "object"
                    ),
                    None,
                )
                if object_node is None:
                    continue
                properties = _object_properties(object_node, source)
                name_value = properties.get("name")
                name_candidate: Any = (
                    _literal(_text(name_value, source))
                    if name_value is not None
                    else None
                )
                if not isinstance(name_candidate, str):
                    parent = node.parent
                    if parent is not None and parent.type == "variable_declarator":
                        variable = parent.child_by_field_name("name")
                        name_candidate = (
                            _text(variable, source)
                            if variable is not None
                            else None
                        )
                if not isinstance(name_candidate, str):
                    continue
                name = name_candidate
                key = (name, node.start_byte)
                if key in seen:
                    continue
                seen.add(key)
                description_value = properties.get("description")
                description = (
                    _literal(_text(description_value, source))
                    if description_value is not None
                    else ""
                )
                schema_node = next(
                    (
                        properties[key_name]
                        for key_name in (
                            "inputSchema",
                            "input_schema",
                            "parameters",
                            "schema",
                        )
                        if key_name in properties
                    ),
                    None,
                )
                handler_node = properties.get("execute") or properties.get("handler")
                handler = (
                    _last_identifier(_text(handler_node, source))
                    if handler_node is not None
                    else name
                )
                mutating_node = (
                    properties.get("mutatesState")
                    or properties.get("mutates_state")
                    or properties.get("mutating")
                )
                approval_node = (
                    properties.get("requiresApproval")
                    or properties.get("requires_approval")
                )
                mutating = (
                    _literal(_text(mutating_node, source))
                    if mutating_node is not None
                    else None
                )
                approval = (
                    _literal(_text(approval_node, source))
                    if approval_node is not None
                    else None
                )
                tool = _tool_definition(
                    name=name,
                    description=description if isinstance(description, str) else "",
                    schema=_jsonish_schema(schema_node, source),
                    handler=handler,
                    framework=framework,
                    relative=relative,
                    node=node,
                    mutates_state=mutating if isinstance(mutating, bool) else None,
                    requires_approval=(
                        approval if isinstance(approval, bool) else None
                    ),
                )
                contribution.tools.append(tool)
                contribution.evidence.append(
                    DiscoveryEvidence(
                        kind="source",
                        path=relative,
                        detail=(
                            f"Discovered {framework}(...) TypeScript tool "
                            f"{name} at line {tool.source_line}"
                        ),
                        confidence=0.95,
                        adapter_id=self.id,
                        span=tool.source_span,
                    )
                )
        return contribution
