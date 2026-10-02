# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from typing import Any, Literal

from policy_authoring.adapters.base import AdapterCapabilities, PolicyTargetAdapter
from policy_authoring.adapters.rendering import render_condition
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompatibilityItem,
    CompilationResult,
    Condition,
    GeneratedArtifact,
    ProjectDefinition,
)


class CedarAdapter(PolicyTargetAdapter):
    name = "cedar"
    capability_version = "2"
    capabilities = AdapterCapabilities(
        supported_decisions=("allow", "deny"),
        lowered_decisions=("warn", "escalate"),
        supported_default_decisions=("deny",),
        supported_operators=(
            "equals",
            "not_equals",
            "in",
            "not_in",
            "exists",
            "greater_than",
            "greater_than_or_equal",
            "less_than",
            "less_than_or_equal",
            "all",
            "any",
            "not",
        ),
        supported_types=("string", "integer", "boolean", "array"),
    )

    @staticmethod
    def _path(value: str) -> str:
        if value.startswith("principal."):
            return value
        if value.startswith("resource."):
            return value
        return f"context.{value}"

    @staticmethod
    def _cedar_type(value: str) -> str:
        return {
            "string": "String",
            "integer": "Long",
            "number": "Long",
            "boolean": "Bool",
            "array": "Set",
            "object": "Record",
        }.get(value, "String")

    @classmethod
    def _insert_schema_path(
        cls,
        attributes: dict[str, Any],
        path: str,
        value_type: str,
        required: bool,
    ) -> None:
        parts = path.split(".")
        current = attributes
        for index, part in enumerate(parts):
            is_leaf = index == len(parts) - 1
            if is_leaf:
                cedar_type = cls._cedar_type(value_type)
                entry: dict[str, Any] = {
                    "type": cedar_type,
                    "required": required,
                }
                if cedar_type == "Set":
                    entry["element"] = {"type": "String"}
                elif cedar_type == "Record":
                    entry["attributes"] = {}
                current[part] = entry
                continue
            entry = current.setdefault(
                part,
                {
                    "type": "Record",
                    "required": False,
                    "attributes": {},
                },
            )
            if required:
                entry["required"] = True
            current = entry["attributes"]

    @classmethod
    def _context_schema(
        cls,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        tool = next(item for item in project.tools if item.name == policy.tool)
        required_arguments = set(tool.input_schema.get("required", []))
        for name, schema in tool.input_schema.get("properties", {}).items():
            cls._insert_schema_path(
                attributes,
                f"action.arguments.{name}",
                schema.get("type", "string"),
                name in required_arguments,
            )
        for item in project.context.attributes:
            if item.trust in {"model_provided", "untrusted"}:
                continue
            cls._insert_schema_path(
                attributes,
                item.path,
                item.type,
                False,
            )
        return {"type": "Record", "attributes": attributes}

    @classmethod
    def _existence_guard(cls, path: str) -> str:
        rendered = cls._path(path)
        if not rendered.startswith("context."):
            return ""
        segments = rendered.split(".")
        return " && ".join(
            f"{'.'.join(segments[:index])} has {segments[index]}"
            for index in range(1, len(segments))
        )

    @classmethod
    def _render_condition(cls, condition: Condition) -> str:
        if condition.operator == "all":
            return " && ".join(
                f"({cls._render_condition(child)})" for child in condition.conditions
            )
        if condition.operator == "any":
            return " || ".join(
                f"({cls._render_condition(child)})" for child in condition.conditions
            )
        if condition.operator == "not":
            return f"!({cls._render_condition(condition.conditions[0])})"

        rendered = render_condition(
            condition,
            cls._path,
            dialect="cedar",
        )
        if condition.operator == "exists":
            return rendered

        paths = []
        for operand in (condition.left, condition.right):
            if operand is not None and operand.path is not None:
                guard = cls._existence_guard(operand.path)
                if guard:
                    paths.append(guard)
        if not paths:
            return rendered
        guards = " && ".join(f"({guard})" for guard in dict.fromkeys(paths))
        return f"{guards} && ({rendered})"

    def compile(
        self,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> CompilationResult:
        compatibility = []
        if policy.default_decision not in self.capabilities.supported_default_decisions:
            compatibility.append(
                CompatibilityItem(
                    rule_id="default-decision",
                    status="unsupported",
                    detail=(
                        "Cedar output is fail-closed and supports only a deny "
                        "canonical default"
                    ),
                )
            )
        tool = next(item for item in project.tools if item.name == policy.tool)
        unsupported_types = {
            str(schema.get("type"))
            for schema in tool.input_schema.get("properties", {}).values()
            if isinstance(schema, dict) and schema.get("type") in {"number", "object"}
        }
        unsupported_types.update(
            item.type
            for item in project.context.attributes
            if item.type in {"number", "object"}
            and any(
                item.path in rule.condition.model_dump_json() for rule in policy.rules
            )
        )
        if unsupported_types:
            compatibility.append(
                CompatibilityItem(
                    rule_id="tool-schema",
                    status="unsupported",
                    detail=(
                        "Cedar output does not safely represent canonical "
                        f"types: {', '.join(sorted(unsupported_types))}"
                    ),
                )
            )
        statements = []
        for rule in policy.rules:
            status: Literal["supported", "lowered", "unsupported"]
            if rule.decision == "transform":
                status = "unsupported"
                detail = "Cedar authorization policies do not rewrite arguments"
            elif rule.decision in {"warn", "escalate"}:
                status = "lowered"
                detail = (
                    f"{rule.decision} is lowered to fail-closed forbid; the "
                    "runtime binding retains the intended outcome"
                )
            else:
                status = "supported"
                detail = "Compiled to Cedar permit or forbid"
            compatibility.append(
                CompatibilityItem(
                    rule_id=rule.id,
                    status=status,
                    fidelity=(
                        "lossy_fail_closed"
                        if status == "lowered"
                        else "unsupported"
                        if status == "unsupported"
                        else "exact"
                    ),
                    detail=detail,
                )
            )
            if status == "unsupported":
                continue
            effect = "permit" if rule.decision == "allow" else "forbid"
            condition = self._render_condition(rule.condition)
            statements.append(
                "\n".join(
                    [
                        f'@id("{rule.id}")',
                        f'@reason("{rule.reason}")',
                        (
                            f"{effect}(principal, action == "
                            f'Action::"{policy.tool}", resource)'
                        ),
                        f"when {{ {condition} }};",
                    ]
                )
            )
        compatible = not any(item.status == "unsupported" for item in compatibility)
        if not compatible:
            return CompilationResult(
                target=self.name,
                compatible=False,
                compatibility=compatibility,
                artifacts=[],
            )

        schema = {
            "": {
                "entityTypes": {
                    "Agent": {"shape": {"type": "Record", "attributes": {}}},
                    "ToolResource": {"shape": {"type": "Record", "attributes": {}}},
                },
                "actions": {
                    policy.tool: {
                        "appliesTo": {
                            "principalTypes": ["Agent"],
                            "resourceTypes": ["ToolResource"],
                            "context": self._context_schema(policy, project),
                        }
                    }
                },
            }
        }
        mapping = {
            "principal": "principal",
            "resource": "resource",
            "action.arguments": "context.action.arguments",
            "workflow": "context.workflow",
            "environment": "context.environment",
        }
        return CompilationResult(
            target=self.name,
            compatible=True,
            compatibility=compatibility,
            artifacts=[
                GeneratedArtifact(
                    path=f"policy/{policy.metadata.name}.cedar",
                    media_type="text/x-cedar",
                    content="\n\n".join(statements) + "\n",
                ),
                GeneratedArtifact(
                    path="policy/schema.json",
                    media_type="application/json",
                    content=json.dumps(schema, indent=2),
                ),
                GeneratedArtifact(
                    path="policy/context-mapping.json",
                    media_type="application/json",
                    content=json.dumps(mapping, indent=2),
                ),
                GeneratedArtifact(
                    path="policy/source-map.json",
                    media_type="application/json",
                    content=json.dumps(
                        {
                            "policy": policy.metadata.name,
                            "tool": policy.tool,
                            "applies_to": self.source_targets(policy),
                        },
                        indent=2,
                    ),
                ),
            ],
        )
