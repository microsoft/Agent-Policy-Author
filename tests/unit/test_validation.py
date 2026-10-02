# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest

from policy_authoring.domain.models import (
    AgentTrace,
    CanonicalPolicy,
    Condition,
    ContextAttribute,
    ContextContract,
    Operand,
    PolicyMetadata,
    PolicyRule,
    PolicyTestCase,
    ProjectDefinition,
    ToolDefinition,
)
from policy_authoring.domain.validation import (
    require_unique_test_ids,
    validate_policy,
)


def test_rejects_undeclared_context_path(
    example_project: ProjectDefinition,
) -> None:
    policy = CanonicalPolicy(
        metadata=PolicyMetadata(name="invalid-policy"),
        tool="apply_update",
        rules=[
            PolicyRule(
                id="invalid-context",
                decision="deny",
                reason="invalid test",
                condition=Condition(
                    operator="equals",
                    left=Operand(path="workflow.undeclared.value"),
                    right=Operand(literal="x"),
                ),
            )
        ],
    )

    issues = validate_policy(policy, example_project)

    assert len(issues) == 1
    assert issues[0].path == "workflow.undeclared.value"


def test_rejects_duplicate_policy_rule_ids() -> None:
    rule = PolicyRule(
        id="duplicate-rule",
        decision="deny",
        reason="duplicate identity test",
        condition=Condition(
            operator="exists",
            left=Operand(path="principal.id"),
        ),
    )

    with pytest.raises(ValueError, match="duplicate policy rule id"):
        CanonicalPolicy(
            metadata=PolicyMetadata(name="duplicate-policy"),
            tool="apply_update",
            rules=[rule, rule],
        )


def test_rejects_duplicate_project_identities() -> None:
    tool = ToolDefinition(
        name="apply_update",
        input_schema={"type": "object", "properties": {}},
    )
    trace = AgentTrace(id="trace-1", steps=[])

    with pytest.raises(ValueError, match="duplicate tool name"):
        ProjectDefinition(
            name="duplicate-tools",
            tools=[tool, tool],
            context=ContextContract(),
        )
    with pytest.raises(ValueError, match="duplicate trace id"):
        ProjectDefinition(
            name="duplicate-traces",
            tools=[tool],
            context=ContextContract(),
            traces=[trace, trace],
        )


def test_rejects_duplicate_context_and_test_identities() -> None:
    attribute = ContextAttribute(
        path="workflow.approval.valid",
        type="boolean",
        trust="approval_store",
    )
    with pytest.raises(ValueError, match="duplicate context attribute path"):
        ContextContract(attributes=[attribute, attribute])

    case = PolicyTestCase(
        id="duplicate-case",
        description="duplicate identity test",
        context={},
        expected_decision="deny",
    )
    with pytest.raises(ValueError, match="duplicate policy test id"):
        require_unique_test_ids([case, case])
