# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from pathlib import Path

import pytest

from policy_authoring.domain.evaluator import evaluate_policy
from policy_authoring.domain.models import (
    CanonicalPolicy,
    ProjectDefinition,
)
from policy_authoring.recommendation.service import synthesize_policy


def test_generated_policy_allows_valid_and_denies_mutation(
    example_project: ProjectDefinition,
    project_root: Path,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    context = json.loads(
        (project_root / "examples" / "document-update" / "base-context.json").read_text(
            encoding="utf-8"
        )
    )

    assert evaluate_policy(policy, context).decision == "allow"

    context["action"]["arguments"]["digest"] = "000000000000"
    result = evaluate_policy(policy, context)
    assert result.decision == "deny"
    assert "bind-digest" in result.matched_rule_ids


def test_generated_policy_escalates_missing_confirmation(
    example_project: ProjectDefinition,
    project_root: Path,
) -> None:
    policy = synthesize_policy(example_project, "apply_update")
    context = json.loads(
        (project_root / "examples" / "document-update" / "base-context.json").read_text(
            encoding="utf-8"
        )
    )
    context["workflow"].pop("confirmation")

    result = evaluate_policy(policy, context)
    assert result.decision == "escalate"


@pytest.mark.parametrize(
    "operator",
    [
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
    ],
)
def test_incompatible_ordered_comparison_fails_closed(
    operator: str,
) -> None:
    policy = CanonicalPolicy.model_validate(
        {
            "metadata": {"name": "typed-comparison-policy"},
            "tool": "typed_comparison",
            "default_decision": "allow",
            "rules": [
                {
                    "id": "allow-threshold",
                    "decision": "allow",
                    "reason": "Allow values above the reviewed threshold.",
                    "condition": {
                        "operator": operator,
                        "left": {"path": "action.arguments.value"},
                        "right": {"literal": 123},
                    },
                }
            ],
        }
    )

    result = evaluate_policy(
        policy,
        {"action": {"arguments": {"value": "not-a-number"}}},
    )

    assert result.decision == "deny"
    assert result.matched_rule_ids == []
    assert result.reason.startswith(
        "rule_evaluation_error:allow-threshold:"
    )
