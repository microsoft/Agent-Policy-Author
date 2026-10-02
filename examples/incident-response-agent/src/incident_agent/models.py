# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    domain: str
    mutating: bool
    requires_approval: bool
    handler: Any
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class AgentContext:
    tenant_id: str
    environment: str
    region: str
    actor_id: str
    actor_role: str
    session_id: str
    change_window: str


def schema(required: list[str], **properties: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            name: {"type": value} for name, value in properties.items()
        },
    }
