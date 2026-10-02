# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json

import yaml

from policy_authoring.adapters.base import AdapterCapabilities, PolicyTargetAdapter
from policy_authoring.adapters.opa import OpaAdapter
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompilationResult,
    GeneratedArtifact,
    ProjectDefinition,
)
from policy_authoring.testing.generator import build_synthetic_context


class AcsAdapter(PolicyTargetAdapter):
    name = "acs"
    capability_version = "0.4.0-alpha.1"
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
        validation_assurance="contract",
    )

    @staticmethod
    def _sample_policy_input(
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> dict[str, object]:
        arguments: dict[str, object] = {}
        metadata: dict[str, object] = {"policy_authoring": {}}
        policy_state = metadata["policy_authoring"]
        assert isinstance(policy_state, dict)
        for trace in project.traces:
            if trace.outcome != "success":
                continue
            for step in trace.steps:
                if step.type == "tool_result" and step.output is not None:
                    if step.tool == "prepare_update":
                        policy_state["workflow"] = {
                            "prepared": step.output,
                        }
                    elif step.tool.startswith("confirm"):
                        workflow = policy_state.setdefault("workflow", {})
                        assert isinstance(workflow, dict)
                        workflow["confirmation"] = step.output
                elif step.type == "tool_call" and step.tool == policy.tool:
                    arguments = step.arguments or {}
                    return {
                        "intervention_point": policy.interception_point,
                        "policy_target": {
                            "kind": "tool_args",
                            "path": "$.tool_call.args",
                            "value": arguments,
                        },
                        "snapshot": {
                            "tool_call": {
                                "id": "sample-call",
                                "name": policy.tool,
                                "args": arguments,
                            },
                            "metadata": metadata,
                        },
                        "annotations": {},
                        "tool": {
                            "name": policy.tool,
                            "id": policy.tool,
                            "clearance": "internal",
                        },
                    }
        context = build_synthetic_context(project, policy.tool)
        policy_state = {
            key: value
            for key, value in context.items()
            if key not in {"action", "principal", "resource"}
        }
        action = context["action"]
        assert isinstance(action, dict)
        arguments = action.get("arguments", {})
        assert isinstance(arguments, dict)
        return {
            "intervention_point": policy.interception_point,
            "policy_target": {
                "kind": "tool_args",
                "path": "$.tool_call.args",
                "value": arguments,
            },
            "snapshot": {
                "actor": context.get("principal", {}),
                "tool_call": {
                    "id": "sample-call",
                    "name": policy.tool,
                    "args": arguments,
                },
                "metadata": {"policy_authoring": policy_state},
            },
            "annotations": {"synthetic": True},
            "tool": {
                "name": policy.tool,
                "id": policy.tool,
                "clearance": "internal",
            },
        }

    def compile(
        self,
        policy: CanonicalPolicy,
        project: ProjectDefinition,
    ) -> CompilationResult:
        rego = OpaAdapter(acs_input=True).compile(policy, project)
        if not rego.compatible:
            return CompilationResult(
                target=self.name,
                compatible=False,
                compatibility=rego.compatibility,
                artifacts=[],
            )
        package_name = policy.metadata.name.replace("-", "_")
        manifest = {
            "agent_control_specification_version": self.capability_version,
            "metadata": {
                "name": policy.metadata.name,
                "canonical_policy_version": policy.metadata.version,
                "generated_by": "agent-policy-author",
                "target": "microsoft-agent-governance-toolkit",
            },
            "policies": {
                "generated_policy": {
                    "type": "rego",
                    "bundle": "./policy",
                    "query": (f"data.policy_authoring.{package_name}.decision"),
                }
            },
            "intervention_points": {
                policy.interception_point: {
                    "policy_target": "$.tool_call.args",
                    "policy_target_kind": "tool_args",
                    "tool_name_from": "$.tool_call.name",
                    "policy": {"id": "generated_policy"},
                }
            },
            "tools": {
                policy.tool: {
                    "type": "Tool",
                    "id": policy.tool,
                    "clearance": "internal",
                }
            },
        }
        source_map = {
            "canonical_policy": policy.metadata.name,
            "canonical_version": policy.metadata.version,
            "tool": policy.tool,
            "applies_to": self.source_targets(policy),
            "rego_artifacts": [item.path for item in rego.artifacts],
        }
        rego_policy = next(
            item for item in rego.artifacts if item.path.endswith(".rego")
        )
        rego_manifest = next(
            item for item in rego.artifacts if item.path.endswith(".manifest")
        )
        context_mapping = next(
            item
            for item in rego.artifacts
            if item.path.endswith("context-mapping.json")
        )
        return CompilationResult(
            target=self.name,
            compatible=True,
            compatibility=rego.compatibility,
            artifacts=[
                GeneratedArtifact(
                    path="acs/manifest.yaml",
                    media_type="application/yaml",
                    content=yaml.safe_dump(manifest, sort_keys=False),
                ),
                GeneratedArtifact(
                    path=f"acs/policy/{rego_policy.path.split('/')[-1]}",
                    media_type=rego_policy.media_type,
                    content=rego_policy.content,
                ),
                GeneratedArtifact(
                    path="acs/policy/.manifest",
                    media_type=rego_manifest.media_type,
                    content=rego_manifest.content,
                ),
                GeneratedArtifact(
                    path="acs/context-mapping.json",
                    media_type=context_mapping.media_type,
                    content=context_mapping.content,
                ),
                GeneratedArtifact(
                    path="acs/source-map.json",
                    media_type="application/json",
                    content=json.dumps(source_map, indent=2),
                ),
                GeneratedArtifact(
                    path="acs/policy-input.sample.json",
                    media_type="application/json",
                    content=json.dumps(
                        self._sample_policy_input(policy, project),
                        indent=2,
                    ),
                ),
            ],
        )
