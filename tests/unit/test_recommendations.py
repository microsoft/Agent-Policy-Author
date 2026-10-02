# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from policy_authoring.domain.evaluator import evaluate_policy
from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    Operand,
    PolicyMetadata,
    PolicyRule,
    ProjectDefinition,
    ToolDefinition,
)
from policy_authoring.recommendation.service import recommend_policies
from policy_authoring.testing.generator import generate_tests


def test_recommends_trace_bindings_and_route(
    example_project: ProjectDefinition,
) -> None:
    recommendations = recommend_policies(example_project, "apply_update")
    identifiers = {item.id for item in recommendations}

    assert "restrict-route" in identifiers
    assert "bind-digest" in identifiers
    assert "bind-value" in identifiers
    assert "require-confirm-update" in identifiers
    assert "bind-confirmation-operation-id" in identifiers
    assert "bind-confirmation-digest" in identifiers


def test_recommendations_reference_only_trusted_context(
    example_project: ProjectDefinition,
) -> None:
    recommendations = recommend_policies(example_project, "apply_update")
    serialized = "\n".join(item.model_dump_json() for item in recommendations)

    assert "model_provided" not in serialized
    assert "workflow.prepared.digest" in serialized


def test_confirmation_evidence_does_not_leak_to_untraced_tool(
    example_project: ProjectDefinition,
) -> None:
    deploy = ToolDefinition(
        name="deploy_release",
        description="Deploy a release.",
        risk="consequential-write",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "version": {"type": "string"},
                "environment": {"type": "string"},
            },
            "required": ["version", "environment"],
        },
        mutates_state=True,
    )
    project = example_project.model_copy(
        update={"tools": [*example_project.tools, deploy]}
    )

    recommendations = recommend_policies(project, "deploy_release")
    identifiers = {item.id for item in recommendations}

    assert not any("confirm" in identifier for identifier in identifiers)


def test_generated_valid_fixture_satisfies_restriction_and_binding() -> None:
    policy = CanonicalPolicy(
        metadata=PolicyMetadata(name="deploy-release-policy"),
        tool="deploy_release",
        rules=[
            PolicyRule(
                id="restrict-environment",
                decision="deny",
                reason="environment is outside approved values",
                condition=Condition(
                    operator="not_in",
                    left=Operand(path="action.arguments.environment"),
                    values=["production"],
                ),
            ),
            PolicyRule(
                id="bind-environment",
                decision="deny",
                reason="environment differs from prepared state",
                condition=Condition(
                    operator="not_equals",
                    left=Operand(path="action.arguments.environment"),
                    right=Operand(path="workflow.prepared.environment"),
                ),
            ),
            PolicyRule(
                id="allow-valid-action",
                decision="allow",
                reason="all generated constraints passed",
                condition=Condition(
                    operator="all",
                    conditions=[
                        Condition(
                            operator="in",
                            left=Operand(path="action.arguments.environment"),
                            values=["production"],
                        ),
                        Condition(
                            operator="equals",
                            left=Operand(path="action.arguments.environment"),
                            right=Operand(path="workflow.prepared.environment"),
                        ),
                    ],
                ),
            ),
        ],
    )

    cases = generate_tests(
        policy,
        {
            "action": {
                "tool": "deploy_release",
                "arguments": {"environment": "example-environment"},
            },
            "workflow": {
                "prepared": {"environment": "example-environment"}
            },
        },
    )
    valid = cases[0]

    assert valid.context["action"]["arguments"]["environment"] == "production"
    assert valid.context["workflow"]["prepared"]["environment"] == "production"
    assert evaluate_policy(policy, valid.context).decision == "allow"
