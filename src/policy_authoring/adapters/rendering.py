# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from policy_authoring.domain.models import Condition, Operand


def safe_identifier(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value)


def json_literal(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def render_condition(
    condition: Condition,
    path_renderer: Callable[[str], str],
    *,
    dialect: str,
) -> str:
    def operand(value: Operand) -> str:
        if value.path is not None:
            return path_renderer(value.path)
        return json_literal(value.literal)

    operator = condition.operator
    if operator == "all":
        joiner = " && " if dialect in {"cedar", "cerbos"} else "; "
        return joiner.join(
            f"({render_condition(child, path_renderer, dialect=dialect)})"
            for child in condition.conditions
        )
    if operator == "any":
        joiner = " || " if dialect in {"cedar", "cerbos"} else " or "
        return joiner.join(
            f"({render_condition(child, path_renderer, dialect=dialect)})"
            for child in condition.conditions
        )
    if operator == "not":
        child = condition.conditions[0]
        if dialect == "rego" and child.operator == "exists" and child.left:
            return f"not {operand(child.left)}"
        inner = render_condition(child, path_renderer, dialect=dialect)
        return f"!({inner})" if dialect in {"cedar", "cerbos"} else f"not {inner}"
    if condition.left is None:
        raise ValueError(f"{operator} has no left operand")
    left = operand(condition.left)
    if operator == "exists":
        if dialect == "rego":
            return f"{left} != null"
        if dialect == "cerbos":
            return f"has({left})"
        segments = left.split(".")
        checks = [
            f"{'.'.join(segments[:index])} has {segments[index]}"
            for index in range(1, len(segments))
        ]
        return " && ".join(checks)
    if operator in {"in", "not_in"}:
        values = json_literal(condition.values)
        if dialect in {"rego", "cerbos"}:
            expression = f"{left} in {values}"
        else:
            expression = f"{values}.contains({left})"
        if operator == "not_in":
            return f"not {expression}" if dialect == "rego" else f"!({expression})"
        return expression
    if condition.right is None:
        raise ValueError(f"{operator} has no right operand")
    right = operand(condition.right)
    symbols = {
        "equals": "==",
        "not_equals": "!=",
        "greater_than": ">",
        "greater_than_or_equal": ">=",
        "less_than": "<",
        "less_than_or_equal": "<=",
    }
    return f"{left} {symbols[operator]} {right}"
