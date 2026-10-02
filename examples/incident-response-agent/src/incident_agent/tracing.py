# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TraceRecorder:
    def __init__(self, path: Path, session_id: str) -> None:
        self.path = path
        self.session_id = session_id
        self.sequence = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def _append(self, record: dict[str, Any]) -> None:
        self.sequence += 1
        record.update(
            {
                "spec": "agent-hooks/0.1",
                "timestamp": datetime.now(UTC).isoformat(),
                "sequence": self.sequence,
                "agent": {
                    "id": "synthetic-incident-response-agent",
                    "framework": "deterministic-planner",
                },
                "session": {"id": self.session_id},
            }
        )
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def invoke(
        self,
        name: str,
        arguments: dict[str, Any],
        handler: Callable[..., dict[str, Any] | list[dict[str, Any]]],
    ) -> dict[str, Any] | list[dict[str, Any]]:
        call_id = f"call-{self.sequence + 1:04d}"
        self._append(
            {
                "interception_point": "pre_tool_call",
                "tool_call": {"id": call_id, "name": name, "args": arguments},
                "target": arguments,
            }
        )
        try:
            result = handler(**arguments)
        except Exception as exc:
            self._append(
                {
                    "interception_point": "post_tool_call",
                    "tool_call": {"id": call_id, "name": name, "args": arguments},
                    "tool_result": {
                        "status": "error",
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    },
                }
            )
            raise
        self._append(
            {
                "interception_point": "post_tool_call",
                "tool_call": {"id": call_id, "name": name, "args": arguments},
                "tool_result": result,
                "target": result,
            }
        )
        return result
