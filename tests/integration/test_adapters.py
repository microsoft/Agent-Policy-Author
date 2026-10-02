# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from pathlib import Path

import pytest
import yaml

from policy_authoring.adapters.registry import default_registry
from policy_authoring.domain.models import ProjectDefinition
from policy_authoring.recommendation.service import synthesize_policy
from policy_authoring.workspace.validation import validate_target


def test_all_target_adapters_compile(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    registry = default_registry()

    results = {
        target: registry.get(target).compile(policy, example_project)
        for target in registry.names
    }

    assert set(results) == {"acs", "agent-hooks", "cedar", "cerbos", "opa"}
    assert all(result.compatible for result in results.values())
    assert all(result.artifacts for result in results.values())


def test_generated_structured_artifacts_parse(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    registry = default_registry()
    results = [
        registry.get(target).compile(policy, example_project)
        for target in registry.names
    ]

    for result in results:
        for artifact in result.artifacts:
            if artifact.media_type == "application/json":
                json.loads(artifact.content)
            elif artifact.media_type == "application/yaml":
                assert isinstance(yaml.safe_load(artifact.content), dict)


def test_acs_artifacts_target_current_agent_governance_toolkit_contract(
    example_project: ProjectDefinition,
    tmp_path: Path,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    result = default_registry().get("acs").compile(policy, example_project)
    target = tmp_path / "acs"
    for artifact in result.artifacts:
        path = target / artifact.path.removeprefix("acs/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")

    manifest = yaml.safe_load(
        (target / "manifest.yaml").read_text(encoding="utf-8")
    )
    assert manifest["agent_control_specification_version"] == "0.4.0-alpha.1"
    assert manifest["metadata"]["target"] == (
        "microsoft-agent-governance-toolkit"
    )
    assert manifest["intervention_points"]["pre_tool_call"] == {
        "policy_target": "$.tool_call.args",
        "policy_target_kind": "tool_args",
        "tool_name_from": "$.tool_call.name",
        "policy": {"id": "generated_policy"},
    }
    rego = next(target.rglob("*.rego")).read_text(encoding="utf-8")
    assert '"evidence":{"matched_rule_ids":' in rego
    validation = validate_target("acs", target)
    assert validation["status"] != "failed"
    assert "AGT ACS 0.4.0-alpha.1 contract accepted" in validation["detail"]

    manifest["agent_control_specification_version"] = "0.3.1-beta"
    (target / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    stale_validation = validate_target("acs", target)
    assert stale_validation["status"] == "failed"
    assert "must target version 0.4.0-alpha.1" in stale_validation["detail"]


def test_artifacts_keep_canonical_rule_ids(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    registry = default_registry()
    required = {rule.id for rule in policy.rules}

    for target in ("opa", "cedar", "cerbos", "acs"):
        result = registry.get(target).compile(policy, example_project)
        combined = "\n".join(item.content for item in result.artifacts)
        for rule_id in required:
            assert rule_id in combined


def test_agent_hooks_fixture_has_required_pre_tool_fields(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    result = (
        default_registry()
        .get("agent-hooks")
        .compile(
            policy,
            example_project,
        )
    )
    fixture = next(
        artifact
        for artifact in result.artifacts
        if artifact.path.endswith("conformance-context.json")
    )
    payload = json.loads(fixture.content)

    assert payload["interception_point"] == "pre_tool_call"
    assert payload["target"] == payload["tool_call"]["args"]
    assert payload["tool_call"]["name"] == "apply_update"


def test_generated_artifacts_include_policy_source_targets(
    project_root: Path,
) -> None:
    from policy_authoring.discovery import discover_project

    root = project_root / "examples" / "discovery-agent"
    report = discover_project(root, allowed_roots=(project_root,))
    proposal = report.proposals[0]
    registry = default_registry()

    assert proposal.policy.source_targets
    assert proposal.policy.source_targets[0].path == "agent.py"
    for target in registry.names:
        result = registry.get(target).compile(
            proposal.policy,
            report.project,
        )
        combined = "\n".join(item.content for item in result.artifacts)
        assert "agent.py" in combined
        assert "apply_update" in combined


def test_cedar_guards_optional_attribute_access(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    result = default_registry().get("cedar").compile(policy, example_project)
    cedar = next(
        artifact.content
        for artifact in result.artifacts
        if artifact.path.endswith(".cedar")
    )

    assert "context has workflow" in cedar
    assert "context.workflow has confirmation" in cedar
    assert "context.workflow.confirmation has confirmed" in cedar


def test_cedar_rejects_unrepresentable_number_schema(
    example_project: ProjectDefinition,
) -> None:
    project = example_project.model_copy(deep=True)
    tool = next(item for item in project.tools if item.name == "apply_update")
    tool.input_schema["properties"]["amount"] = {"type": "number"}
    policy = synthesize_policy(project, "apply_update")

    result = default_registry().get("cedar").compile(policy, project)

    assert not result.compatible
    assert result.artifacts == []
    assert any(
        item.rule_id == "tool-schema" and item.status == "unsupported"
        for item in result.compatibility
    )


def test_fail_closed_targets_lower_warn_to_deny(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    policy.rules[0] = policy.rules[0].model_copy(update={"decision": "warn"})
    registry = default_registry()

    cedar = registry.get("cedar").compile(policy, example_project)
    cedar_policy = next(
        item.content for item in cedar.artifacts if item.path.endswith(".cedar")
    )
    assert "forbid(" in cedar_policy
    assert "permit(" not in cedar_policy.split('@id("', 1)[1].split("\n\n", 1)[0]

    cerbos = registry.get("cerbos").compile(policy, example_project)
    cerbos_policy = next(
        yaml.safe_load(item.content)
        for item in cerbos.artifacts
        if item.path.endswith(".yaml")
    )
    first_rule = cerbos_policy["resourcePolicy"]["rules"][0]
    assert first_rule["effect"] == "EFFECT_DENY"


def test_implicit_deny_targets_reject_non_deny_default(
    example_project: ProjectDefinition,
) -> None:
    policy = synthesize_policy(example_project, "apply_update").model_copy(
        update={"default_decision": "allow"}
    )
    registry = default_registry()

    for target in ("cedar", "cerbos"):
        result = registry.get(target).compile(policy, example_project)
        assert not result.compatible
        assert result.artifacts == []
        assert any(
            item.rule_id == "default-decision" and item.status == "unsupported"
            for item in result.compatibility
        )


def test_adapter_capability_contracts_are_explicit() -> None:
    registry = default_registry()

    for target in registry.names:
        adapter = registry.get(target)
        assert adapter.capabilities.supported_decisions
        assert adapter.capabilities.supported_default_decisions
        assert adapter.capabilities.supported_operators
        assert adapter.capabilities.supported_types


def test_agent_hooks_declares_and_uses_opa_evaluator(
    example_project: ProjectDefinition,
) -> None:
    registry = default_registry()
    adapter = registry.get("agent-hooks")

    assert adapter.capabilities.dependencies == ("opa",)
    with pytest.raises(ValueError, match="requires companion target"):
        registry.validate_selection(["agent-hooks"])
    registry.validate_selection(["opa", "agent-hooks"])
    assert registry.order_selection(["agent-hooks", "opa"]) == [
        "opa",
        "agent-hooks",
    ]

    policy = synthesize_policy(example_project, "apply_update")
    result = adapter.compile(policy, example_project)
    binding = next(
        json.loads(item.content)
        for item in result.artifacts
        if item.path.endswith("binding.json")
    )
    evaluator = binding["spec"]["evaluator"]
    assert evaluator["target"] == "opa"
    assert evaluator["failureMode"] == "deny"
    assert evaluator["artifact"] == "../../opa/policy/apply_update_policy.rego"
    assert evaluator["query"].startswith("data.policy_authoring.")
