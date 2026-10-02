# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json

from policy_authoring.adapters.base import AdapterCapabilities, PolicyTargetAdapter
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompatibilityItem,
    CompilationResult,
    GeneratedArtifact,
    ProjectDefinition,
)


class AgentHooksAdapter(PolicyTargetAdapter):
    name = "agent-hooks"
    capabilities = AdapterCapabilities(
        supported_decisions=("allow", "deny", "warn", "escalate", "transform"),
        lowered_decisions=(),
        supported_default_decisions=(
            "allow",
            "deny",
            "warn",
            "escalate",
            "transform",
        ),
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
        dependencies=("opa",),
        validation_assurance="contract",
    )

    def compile(
        self,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> CompilationResult:
        compatibility = [
            CompatibilityItem(
                rule_id=rule.id,
                status="supported",
                detail="Rule is evaluated by the configured policy interceptor",
            )
            for rule in policy.rules
        ]
        context_mapping = {
            "spec": "agent-hooks/0.1",
            "interception_point": policy.interception_point,
            "target": "action.arguments",
            "trusted_attributes": [
                {
                    "canonical_path": item.path,
                    "trust": item.trust,
                    "source": item.source,
                    "transport": (
                        "agent_context_extension"
                        if item.source is None
                        else "trusted_resolver"
                    ),
                }
                for item in self.trusted_context(project).attributes
            ],
        }
        verdict_mapping = {
            "allow": {"decision": "allow"},
            "deny": {"decision": "deny"},
            "warn": {
                "decision": "allow",
                "warnings": "copy_from_engine_reason",
            },
            "escalate": {
                "decision": "deny",
                "approval": {},
            },
            "transform": {
                "decision": "transform",
                "transform": "copy_from_engine_transform",
            },
        }
        binding = {
            "apiVersion": "policyauthor.dev/v1alpha1",
            "kind": "AgentHooksBinding",
            "metadata": {
                "name": policy.metadata.name,
                "policyVersion": policy.metadata.version,
            },
            "spec": {
                "agentHooksVersion": "0.1",
                "interceptionPoint": policy.interception_point,
                "match": {"tool": policy.tool},
                "compositionProfile": "parallel/strictest",
                "evaluator": {
                    "target": "opa",
                    "artifact": (
                        "../../opa/policy/"
                        f"{policy.metadata.name.replace('-', '_')}.rego"
                    ),
                    "query": (
                        "data.policy_authoring."
                        f"{policy.metadata.name.replace('-', '_')}.decision"
                    ),
                    "requestSchema": "conformance-context.json",
                    "responseSchema": "verdict-mapping.json",
                    "failureMode": "deny",
                },
                "contextMapping": "context-mapping.json",
                "verdictMapping": "verdict-mapping.json",
                "sourceTargets": self.source_targets(policy),
            },
        }
        fixture = {
            "spec": "agent-hooks/0.1",
            "interception_point": policy.interception_point,
            "timestamp": "2026-09-10T00:00:00Z",
            "sequence": 1,
            "agent": {"id": "example-agent", "framework": "example"},
            "session": {"id": "example-session"},
            "tool_call": {
                "id": "call-1",
                "name": policy.tool,
                "args": {},
            },
            "target": {},
        }
        return CompilationResult(
            target=self.name,
            compatible=True,
            compatibility=compatibility,
            artifacts=[
                GeneratedArtifact(
                    path="agent-hooks/binding.json",
                    media_type="application/json",
                    content=json.dumps(binding, indent=2),
                ),
                GeneratedArtifact(
                    path="agent-hooks/context-mapping.json",
                    media_type="application/json",
                    content=json.dumps(context_mapping, indent=2),
                ),
                GeneratedArtifact(
                    path="agent-hooks/verdict-mapping.json",
                    media_type="application/json",
                    content=json.dumps(verdict_mapping, indent=2),
                ),
                GeneratedArtifact(
                    path="agent-hooks/conformance-context.json",
                    media_type="application/json",
                    content=json.dumps(fixture, indent=2),
                ),
                GeneratedArtifact(
                    path="agent-hooks/source-map.json",
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
