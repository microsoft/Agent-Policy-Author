# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json

from policy_authoring.adapters.base import AdapterCapabilities, PolicyTargetAdapter
from policy_authoring.adapters.rendering import render_condition, safe_identifier
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompatibilityItem,
    CompilationResult,
    GeneratedArtifact,
    ProjectDefinition,
)


class OpaAdapter(PolicyTargetAdapter):
    name = "opa"
    capabilities = AdapterCapabilities(
        supported_decisions=("allow", "deny", "warn", "escalate"),
        lowered_decisions=(),
        supported_default_decisions=("allow", "deny", "warn", "escalate"),
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
        supported_types=("string", "number", "integer", "boolean", "object", "array"),
    )

    def __init__(self, *, acs_input: bool = False) -> None:
        self.acs_input = acs_input

    def _path(self, value: str) -> str:
        if not self.acs_input:
            return f"input.{value}"
        if value.startswith("action.arguments."):
            suffix = value.removeprefix("action.arguments.")
            return f"input.policy_target.value.{suffix}"
        if value.startswith("principal."):
            suffix = value.removeprefix("principal.")
            return f"input.snapshot.actor.{suffix}"
        return f"input.snapshot.metadata.policy_authoring.{value}"

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
                        f"{self.name} does not support canonical default decision "
                        f"{policy.default_decision}"
                    ),
                )
            )
        for rule in policy.rules:
            supported = rule.decision != "transform"
            compatibility.append(
                CompatibilityItem(
                    rule_id=rule.id,
                    status="supported" if supported else "unsupported",
                    detail=(
                        "Compiled to a native structured Rego decision"
                        if supported
                        else "Transform payloads are not modeled by this MVP"
                    ),
                )
            )
        if any(item.status == "unsupported" for item in compatibility):
            return CompilationResult(
                target=self.name,
                compatible=False,
                compatibility=compatibility,
                artifacts=[],
            )

        package = safe_identifier(policy.metadata.name)
        lines = [
            f"package policy_authoring.{package}",
            "",
            "import rego.v1",
            "",
        ]
        groups: dict[str, list[str]] = {
            "deny": [],
            "escalate": [],
            "warn": [],
            "allow": [],
        }
        for rule in policy.rules:
            rule_name = safe_identifier(rule.id)
            collection = f"{rule.decision}_matches"
            groups[rule.decision].append(rule.id)
            condition = render_condition(
                rule.condition,
                self._path,
                dialect="rego",
            )
            lines.extend(
                [
                    (
                        f'{collection} contains {{"rule_id":{json.dumps(rule.id)},'
                        f'"reason":{json.dumps(rule.reason)}}} if {{'
                    ),
                    f"    {condition}",
                    "}",
                    "",
                ]
            )
            if rule_name == "":
                raise AssertionError("validated rule ID cannot be empty")

        lines.extend(
            [
                (
                    "default decision := "
                    f'{{"decision":{json.dumps(policy.default_decision)},'
                    '"reason":"default_decision",'
                    + (
                        '"evidence":{"matched_rule_ids":[]}}'
                        if self.acs_input
                        else '"matched_rule_ids":[]}'
                    )
                ),
                "",
            ]
        )
        precedence = ["deny", "escalate", "warn", "allow"]
        higher: list[str] = []
        for decision in precedence:
            if not groups[decision]:
                continue
            conditions = [f"count({decision}_matches) > 0"]
            conditions.extend(f"count({item}_matches) == 0" for item in higher)
            lines.extend(
                [
                    (
                        f'decision := {{"decision":{json.dumps(decision)},'
                        f'"reason":{decision}_matches_list[0].reason,'
                        + (
                            f'"evidence":{{"matched_rule_ids":[item.rule_id | '
                            f"some item in {decision}_matches]}}}} if {{"
                            if self.acs_input
                            else f'"matched_rule_ids":[item.rule_id | '
                            f"some item in {decision}_matches]}} if {{"
                        )
                    ),
                    *[f"    {item}" for item in conditions],
                    (
                        f"    {decision}_matches_list := "
                        f"sort([item | some item in {decision}_matches])"
                    ),
                    "}",
                    "",
                ]
            )
            higher.append(decision)

        source_map = {
            "policy": policy.metadata.name,
            "tool": policy.tool,
            "applies_to": self.source_targets(policy),
            "rules": {
                rule.id: {
                    "canonical": f"rules[{index}]",
                    "target": f"{rule.decision}_matches",
                }
                for index, rule in enumerate(policy.rules)
            },
        }
        context_mapping = {
            item.path: {
                "target": self._path(item.path),
                "trust": item.trust,
                "source": item.source,
            }
            for item in self.trusted_context(project).attributes
        }
        prefix = "policy" if not self.acs_input else "policy/acs"
        return CompilationResult(
            target=self.name,
            compatible=True,
            compatibility=compatibility,
            artifacts=[
                GeneratedArtifact(
                    path=f"{prefix}/{package}.rego",
                    media_type="text/x-rego",
                    content="\n".join(lines).rstrip() + "\n",
                ),
                GeneratedArtifact(
                    path=f"{prefix}/context-mapping.json",
                    media_type="application/json",
                    content=json.dumps(context_mapping, indent=2),
                ),
                GeneratedArtifact(
                    path=f"{prefix}/source-map.json",
                    media_type="application/json",
                    content=json.dumps(source_map, indent=2),
                ),
                GeneratedArtifact(
                    path=f"{prefix}/.manifest",
                    media_type="application/json",
                    content=json.dumps(
                        {
                            "revision": (
                                f"{policy.metadata.name}-{policy.metadata.version}"
                            ),
                            "roots": ["policy_authoring"],
                        },
                        indent=2,
                    ),
                ),
            ],
        )
