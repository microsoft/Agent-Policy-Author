# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from typing import Literal

import yaml

from policy_authoring.adapters.base import AdapterCapabilities, PolicyTargetAdapter
from policy_authoring.adapters.rendering import render_condition
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompatibilityItem,
    CompilationResult,
    GeneratedArtifact,
    ProjectDefinition,
)


class CerbosAdapter(PolicyTargetAdapter):
    name = "cerbos"
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
        supported_types=("string", "number", "integer", "boolean", "object", "array"),
        validation_assurance="contract",
    )

    @staticmethod
    def _path(value: str) -> str:
        if value.startswith("principal."):
            return "request.principal.attr." + value.removeprefix("principal.")
        if value.startswith("resource."):
            return "request.resource.attr." + value.removeprefix("resource.")
        return "request.resource.attr." + value

    def compile(
        self,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> CompilationResult:
        compatibility = []
        rules = []
        if policy.default_decision not in self.capabilities.supported_default_decisions:
            compatibility.append(
                CompatibilityItem(
                    rule_id="default-decision",
                    status="unsupported",
                    detail=(
                        "Cerbos output uses implicit deny and supports only a deny "
                        "canonical default"
                    ),
                )
            )
        for rule in policy.rules:
            status: Literal["supported", "lowered", "unsupported"]
            if rule.decision == "transform":
                status = "unsupported"
                detail = "Cerbos resource policies do not transform tool arguments"
            elif rule.decision in {"warn", "escalate"}:
                status = "lowered"
                detail = f"{rule.decision} is lowered to EFFECT_DENY"
            else:
                status = "supported"
                detail = "Compiled to a Cerbos resource rule"
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
            effect = "EFFECT_ALLOW" if rule.decision == "allow" else "EFFECT_DENY"
            rules.append(
                {
                    "name": rule.id,
                    "actions": [policy.tool],
                    "roles": ["*"],
                    "effect": effect,
                    "condition": {
                        "match": {
                            "expr": render_condition(
                                rule.condition,
                                self._path,
                                dialect="cerbos",
                            )
                        }
                    },
                }
            )
        compatible = not any(item.status == "unsupported" for item in compatibility)
        if not compatible:
            return CompilationResult(
                target=self.name,
                compatible=False,
                compatibility=compatibility,
                artifacts=[],
            )
        document = {
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "version": str(policy.metadata.version),
                "resource": f"agent_tool_{policy.tool}",
                "rules": rules,
            },
        }
        mapping = {
            item.path: {
                "target": self._path(item.path),
                "trust": item.trust,
                "source": item.source,
            }
            for item in self.trusted_context(project).attributes
        }
        return CompilationResult(
            target=self.name,
            compatible=True,
            compatibility=compatibility,
            artifacts=[
                GeneratedArtifact(
                    path=f"policies/{policy.metadata.name}.yaml",
                    media_type="application/yaml",
                    content=yaml.safe_dump(document, sort_keys=False),
                ),
                GeneratedArtifact(
                    path="context-mapping.json",
                    media_type="application/json",
                    content=json.dumps(mapping, indent=2),
                ),
                GeneratedArtifact(
                    path="source-map.json",
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
