# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from policy_authoring.discovery.contracts import (
    BaseDiscoveryAdapter,
    DiscoveryContext,
    DiscoveryContribution,
)
from policy_authoring.domain.models import (
    AgentTrace,
    ContextAttribute,
    DiscoveryEvidence,
    SourceSpan,
    TraceStep,
)


def _read_trace_documents(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    values: list[Any]
    if path.suffix.lower() == ".jsonl":
        values = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_number}:{exc.colno}: malformed supported "
                    f"Agent Hooks JSONL trace: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise ValueError(
                    f"{path}:{line_number}: supported Agent Hooks JSONL trace "
                    "records must be JSON objects"
                )
            values.append(value)
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path}:{exc.lineno}:{exc.colno}: malformed supported "
                f"Agent Hooks JSON trace: {exc.msg}"
            ) from exc
        values = parsed if isinstance(parsed, list) else [parsed]
    return [item for item in values if isinstance(item, dict)]


class AgentHooksTraceAdapter(BaseDiscoveryAdapter):
    id = "agent-hooks-trace"
    suffixes = frozenset({".json", ".jsonl"})

    def supports(self, path: Path, context: DiscoveryContext) -> bool:
        return super().supports(path, context) and any(
            token in path.name.lower()
            for token in ("trace", "hook", "interception")
        )

    def discover(
        self,
        path: Path,
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        documents = _read_trace_documents(path)
        if not documents or not any(
            str(item.get("spec", "")).startswith("agent-hooks/")
            or "interception_point" in item
            for item in documents
        ):
            return DiscoveryContribution()
        sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in documents:
            session = item.get("session", {})
            session_id = (
                session.get("id")
                if isinstance(session, dict)
                else item.get("session_id")
            )
            sessions[str(session_id or path.stem)].append(item)
        traces: list[AgentTrace] = []
        for session_id, records in sorted(sessions.items()):
            steps: list[TraceStep] = []
            for record in sorted(
                records,
                key=lambda item: int(item.get("sequence", 0)),
            ):
                point = record.get("interception_point")
                tool_call = record.get("tool_call", {})
                if point == "pre_tool_call" and isinstance(tool_call, dict):
                    steps.append(
                        TraceStep(
                            type="tool_call",
                            tool=str(tool_call.get("name", "unknown_tool")),
                            arguments=(
                                tool_call.get("args")
                                if isinstance(tool_call.get("args"), dict)
                                else {}
                            ),
                        )
                    )
                elif point == "post_tool_call" and isinstance(tool_call, dict):
                    target = record.get("target")
                    result = record.get("tool_result", target)
                    steps.append(
                        TraceStep(
                            type="tool_result",
                            tool=str(tool_call.get("name", "unknown_tool")),
                            output=(
                                result
                                if isinstance(result, dict)
                                else {"value": result}
                            ),
                        )
                    )
            if steps:
                traces.append(
                    AgentTrace(
                        id=f"agent-hooks-{session_id}",
                        steps=steps,
                    )
                )
            if len(traces) >= context.limits.max_traces:
                break
        if not traces:
            return DiscoveryContribution()
        relative = context.relative(path)
        span = SourceSpan(path=relative, start_line=1, start_column=1)
        return DiscoveryContribution(
            traces=traces,
            evidence=[
                DiscoveryEvidence(
                    kind="trace",
                    path=relative,
                    detail=(
                        f"Imported {len(traces)} Agent Hooks session trace(s)"
                    ),
                    confidence=1.0,
                    adapter_id=self.id,
                    span=span,
                )
            ],
        )

    def finalize(
        self,
        files: list[Path],
        tools: list[Any],
        traces: list[AgentTrace],
        context: DiscoveryContext,
    ) -> DiscoveryContribution:
        attributes: dict[str, ContextAttribute] = {}
        for trace in traces:
            for step in trace.steps:
                if step.type != "tool_result" or not step.output:
                    continue
                if step.tool.startswith("prepare"):
                    prefix = "workflow.prepared"
                    trust = "workflow_store"
                elif step.tool.startswith("confirm"):
                    prefix = "workflow.confirmation"
                    trust = "approval_store"
                else:
                    continue
                for name, value in step.output.items():
                    if isinstance(value, (dict, list)):
                        continue
                    value_type = (
                        "boolean"
                        if isinstance(value, bool)
                        else "integer"
                        if isinstance(value, int)
                        else "number"
                        if isinstance(value, float)
                        else "string"
                    )
                    path = f"{prefix}.{name}"
                    attributes[path] = ContextAttribute(
                        path=path,
                        type=value_type,  # type: ignore[arg-type]
                        trust=trust,  # type: ignore[arg-type]
                        source=f"{step.tool}.output.{name}",
                    )
        return DiscoveryContribution(
            context_attributes=sorted(
                attributes.values(),
                key=lambda item: item.path,
            )
        )
