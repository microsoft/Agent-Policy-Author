# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from typing import Any

from policy_authoring.domain.input_validation import validate_action_input


def _context(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": {
            "tool": "apply_update",
            "arguments": arguments,
        }
    }


def test_action_input_gate_applies_complete_json_schema() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["route", "changes"],
        "properties": {
            "route": {"type": "string", "enum": ["primary"]},
            "changes": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["field"],
                    "properties": {"field": {"type": "string"}},
                },
            },
        },
    }

    valid = validate_action_input(
        schema,
        "apply_update",
        _context({"route": "primary", "changes": [{"field": "title"}]}),
    )
    unknown = validate_action_input(
        schema,
        "apply_update",
        _context(
            {
                "route": "primary",
                "changes": [{"field": "title"}],
                "override": True,
            }
        ),
    )
    nested = validate_action_input(
        schema,
        "apply_update",
        _context({"route": "primary", "changes": [{"unexpected": "title"}]}),
    )
    empty = validate_action_input(
        schema,
        "apply_update",
        _context({"route": "primary", "changes": []}),
    )
    wrong_tool = validate_action_input(
        schema,
        "apply_update",
        {
            "action": {
                "tool": "delete_document",
                "arguments": {
                    "route": "primary",
                    "changes": [{"field": "title"}],
                },
            }
        },
    )

    assert valid.passed
    assert not unknown.passed
    assert "override" in unknown.detail
    assert not nested.passed
    assert "field" in nested.detail
    assert not empty.passed
    assert "non-empty" in empty.detail
    assert not wrong_tool.passed
    assert "action.tool must equal" in wrong_tool.detail
