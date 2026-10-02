# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from collections import defaultdict
from typing import Any, Literal

from policy_authoring.domain.evaluator import complement
from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    FunctionalGate,
    Operand,
    PolicyMetadata,
    PolicyProposal,
    PolicyRule,
    ProjectDefinition,
    Recommendation,
    SourceReference,
)


def _leaf_values(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    leaves: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            leaves.update(_leaf_values(item, path))
        else:
            leaves[path] = item
    return leaves


def _successful_calls(
    project: ProjectDefinition,
    target_tool: str,
) -> list[tuple[dict[str, Any], list[tuple[str, dict[str, Any]]]]]:
    samples = []
    for trace in project.traces:
        if trace.outcome != "success":
            continue
        prior_results: list[tuple[str, dict[str, Any]]] = []
        for step in trace.steps:
            if step.type == "tool_call" and step.tool == target_tool:
                samples.append((step.arguments or {}, list(prior_results)))
            if step.type == "tool_result" and step.output is not None:
                prior_results.append((step.tool, step.output))
    return samples


def _context_path_for_source(
    project: ProjectDefinition,
    source: str,
) -> str | None:
    for attribute in project.context.attributes:
        if attribute.source == source and attribute.trust not in {
            "model_provided",
            "untrusted",
        }:
            return attribute.path
    return None


def _trusted_context_path(
    project: ProjectDefinition,
    suffix: str,
) -> str | None:
    return next(
        (
            item.path
            for item in project.context.attributes
            if item.path.endswith(suffix)
            and item.trust not in {"model_provided", "untrusted"}
        ),
        None,
    )


def _presence_recommendation(
    *,
    identifier: str,
    title: str,
    detail: str,
    path: str,
    decision: Literal["deny", "escalate"],
    evidence: list[str],
    confidence: float,
) -> Recommendation:
    return Recommendation(
        id=identifier,
        title=title,
        detail=detail,
        confidence=confidence,
        evidence=evidence,
        rule=PolicyRule(
            id=identifier,
            decision=decision,
            reason=title,
            condition=Condition(
                operator="not",
                conditions=[
                    Condition(
                        operator="exists",
                        left=Operand(path=path),
                    )
                ],
            ),
        ),
    )


def _host_control_recommendations(
    project: ProjectDefinition,
    tool_name: str,
) -> list[Recommendation]:
    tool = next(item for item in project.tools if item.name == tool_name)
    if tool.mutates_state is not True:
        return []
    observations: dict[str, Any] = {
        item.kind: item for item in project.controls if item.target_tool == tool.name
    }
    recommendations: list[Recommendation] = []
    requirements = [
        (
            "operation-id",
            ".operation_id",
            "Bind the action to a host-provided operation identifier",
            "Mutating actions must identify the workflow operation they affect.",
            "operation_binding",
        ),
        (
            "expected-version",
            ".expected_version",
            "Require an expected state version",
            "Mutating actions must reject stale state at the execution boundary.",
            "version_check",
        ),
        (
            "idempotency-key",
            ".idempotency_key",
            "Require an idempotency key",
            "Mutating actions must be safe to retry without duplicate effects.",
            "idempotency",
        ),
    ]
    for identifier, suffix, title, detail, observation_kind in requirements:
        path = _trusted_context_path(project, suffix)
        if path is None:
            continue
        observation = observations.get(observation_kind)
        recommendations.append(
            _presence_recommendation(
                identifier=f"require-{identifier}",
                title=title,
                detail=detail,
                path=path,
                decision="deny",
                evidence=[
                    (
                        observation.detail
                        if observation is not None
                        else f"trusted context attribute discovered at {path}"
                    )
                ],
                confidence=observation.confidence if observation else 0.8,
            )
        )
    if tool.requires_approval is True:
        approval_path = _trusted_context_path(
            project,
            ".approval.valid",
        )
        if approval_path is not None:
            recommendations.append(
                _presence_recommendation(
                    identifier="require-approval-evidence",
                    title="Require host-verified approval evidence",
                    detail=(
                        "The tool metadata declares approval as mandatory; "
                        "the host must resolve approval state before evaluation."
                    ),
                    path=approval_path,
                    decision="escalate",
                    evidence=[
                        "requires_approval=true",
                        f"trusted approval context: {approval_path}",
                    ],
                    confidence=1.0,
                )
            )
            recommendations.append(
                Recommendation(
                    id="require-positive-approval",
                    title="Require a positive approval decision",
                    detail=(
                        "Approval evidence must be valid for the current "
                        "operation and action before execution."
                    ),
                    confidence=1.0,
                    evidence=[
                        "requires_approval=true",
                        "approval resolver must verify operation and payload binding",
                    ],
                    rule=PolicyRule(
                        id="require-positive-approval",
                        decision="escalate",
                        reason="a valid bound approval is required",
                        condition=Condition(
                            operator="not_equals",
                            left=Operand(path=approval_path),
                            right=Operand(literal=True),
                        ),
                    ),
                )
            )
    return recommendations


def recommend_policies(
    project: ProjectDefinition,
    tool_name: str | None = None,
) -> list[Recommendation]:
    recommendations: list[Recommendation] = []
    tools = [
        tool
        for tool in project.tools
        if (tool.risk == "consequential-write" or tool.mutates_state is True)
        and (tool_name is None or tool.name == tool_name)
    ]

    for tool in tools:
        recommendations.extend(_host_control_recommendations(project, tool.name))
        samples = _successful_calls(project, tool.name)
        properties = tool.input_schema.get("properties", {})

        for argument, schema in properties.items():
            enum_values = schema.get("enum") if isinstance(schema, dict) else None
            observed = {
                arguments[argument] for arguments, _ in samples if argument in arguments
            }
            if enum_values and observed and observed < set(enum_values):
                values = sorted(observed, key=str)
                rule_id = f"restrict-{argument.replace('_', '-')}"
                recommendations.append(
                    Recommendation(
                        id=rule_id,
                        title=f"Restrict {argument} to observed safe values",
                        detail=(
                            f"Successful traces used {values}; the schema also "
                            f"permits {sorted(set(enum_values) - observed, key=str)}."
                        ),
                        confidence=0.9,
                        evidence=[
                            f"{len(samples)} successful calls analyzed",
                            f"observed values: {values}",
                        ],
                        rule=PolicyRule(
                            id=rule_id,
                            decision="deny",
                            reason=f"{argument} is outside the approved values",
                            condition=Condition(
                                operator="not_in",
                                left=Operand(path=f"action.arguments.{argument}"),
                                values=values,
                            ),
                        ),
                    )
                )

        candidate_sources: dict[str, list[str]] = defaultdict(list)
        for argument in properties:
            for arguments, prior_results in samples:
                if argument not in arguments:
                    continue
                matches = []
                for source_tool, output in prior_results:
                    for output_path, value in _leaf_values(output).items():
                        if value == arguments[argument]:
                            matches.append(f"{source_tool}.output.{output_path}")
                candidate_sources[argument].extend(matches)

        for argument, sources in candidate_sources.items():
            if not samples or not sources:
                continue
            counts: dict[str, int] = defaultdict(int)
            for source in sources:
                counts[source] += 1
            source, count = max(counts.items(), key=lambda item: item[1])
            if count != len(samples):
                continue
            context_path = _context_path_for_source(project, source)
            if context_path is None:
                continue
            rule_id = f"bind-{argument.replace('_', '-')}"
            recommendations.append(
                Recommendation(
                    id=rule_id,
                    title=f"Bind {argument} to trusted workflow state",
                    detail=(
                        f"The argument matched {source} in every successful "
                        "trace and a trusted context mapping is available."
                    ),
                    confidence=1.0,
                    evidence=[
                        f"{count}/{len(samples)} successful traces matched",
                        f"trusted context: {context_path}",
                    ],
                    rule=PolicyRule(
                        id=rule_id,
                        decision="deny",
                        reason=(f"{argument} differs from trusted workflow state"),
                        condition=Condition(
                            operator="not_equals",
                            left=Operand(path=f"action.arguments.{argument}"),
                            right=Operand(path=context_path),
                        ),
                    ),
                )
            )

        target_traces = [
            trace
            for trace in project.traces
            if trace.outcome == "success"
            and any(
                step.type == "tool_call" and step.tool == tool.name
                for step in trace.steps
            )
        ]
        confirm_tools = {
            step.tool
            for trace in target_traces
            for index, step in enumerate(trace.steps)
            if step.type == "tool_call"
            and step.tool.startswith("confirm")
            and any(
                later.type == "tool_call" and later.tool == tool.name
                for later in trace.steps[index + 1 :]
            )
        }
        for confirm_tool in sorted(confirm_tools):
            appears_before_all = all(
                any(
                    step.type == "tool_call" and step.tool == confirm_tool
                    for step in trace.steps[
                        : next(
                            (
                                index
                                for index, step in enumerate(trace.steps)
                                if step.type == "tool_call" and step.tool == tool.name
                            ),
                            len(trace.steps),
                        )
                    ]
                )
                for trace in target_traces
            )
            if not appears_before_all:
                continue
            confirmed_path = next(
                (
                    item.path
                    for item in project.context.attributes
                    if item.source == f"{confirm_tool}.output.confirmed"
                    and item.trust == "approval_store"
                ),
                None,
            )
            evidence_path = confirmed_path or next(
                (
                    item.path
                    for item in project.context.attributes
                    if item.source
                    and item.source.startswith(f"{confirm_tool}.output.")
                    and item.trust == "approval_store"
                ),
                None,
            )
            if evidence_path is None:
                continue
            rule_id = f"require-{confirm_tool.replace('_', '-')}"
            condition = Condition(
                operator="not",
                conditions=[
                    Condition(
                        operator="exists",
                        left=Operand(path=evidence_path),
                    )
                ],
            )
            recommendations.append(
                Recommendation(
                    id=rule_id,
                    title=f"Require evidence from {confirm_tool}",
                    detail=(
                        f"Every successful {tool.name} trace was preceded by "
                        f"{confirm_tool}."
                    ),
                    confidence=0.95,
                    evidence=[f"trusted evidence path: {evidence_path}"],
                    rule=PolicyRule(
                        id=rule_id,
                        decision="escalate",
                        reason=f"{confirm_tool} evidence is required",
                        condition=condition,
                    ),
                )
            )
            if confirmed_path is not None:
                confirmation_rule_id = (
                    f"require-positive-{confirm_tool.replace('_', '-')}"
                )
                recommendations.append(
                    Recommendation(
                        id=confirmation_rule_id,
                        title=f"Require positive evidence from {confirm_tool}",
                        detail=(
                            f"{confirmed_path} must be true before "
                            f"{tool.name} executes."
                        ),
                        confidence=1.0,
                        evidence=[f"trusted confirmation context: {confirmed_path}"],
                        rule=PolicyRule(
                            id=confirmation_rule_id,
                            decision="escalate",
                            reason=f"{confirm_tool} must explicitly allow",
                            condition=Condition(
                                operator="not_equals",
                                left=Operand(path=confirmed_path),
                                right=Operand(literal=True),
                            ),
                        ),
                    )
                )
            for argument in properties:
                context_path = _context_path_for_source(
                    project,
                    f"{confirm_tool}.output.{argument}",
                )
                if context_path is None:
                    continue
                binding_id = f"bind-confirmation-{argument.replace('_', '-')}"
                recommendations.append(
                    Recommendation(
                        id=binding_id,
                        title=(f"Bind {argument} to {confirm_tool} evidence"),
                        detail=(
                            f"The confirmed {argument} is available from "
                            f"trusted context at {context_path}."
                        ),
                        confidence=1.0,
                        evidence=[f"trusted confirmation context: {context_path}"],
                        rule=PolicyRule(
                            id=binding_id,
                            decision="deny",
                            reason=(
                                f"{argument} differs from confirmed workflow state"
                            ),
                            condition=Condition(
                                operator="not_equals",
                                left=Operand(path=f"action.arguments.{argument}"),
                                right=Operand(path=context_path),
                            ),
                        ),
                    )
                )

    unique: dict[str, Recommendation] = {}
    for recommendation in recommendations:
        unique.setdefault(recommendation.id, recommendation)
    return list(unique.values())


def build_functional_gates(
    project: ProjectDefinition,
    tool_name: str,
    recommendations: list[Recommendation],
) -> list[FunctionalGate]:
    tool = next(item for item in project.tools if item.name == tool_name)
    required = list(tool.input_schema.get("required", []))
    gates = [
        FunctionalGate(
            id=f"validate-{tool_name.replace('_', '-')}-schema",
            stage="schema_validation",
            target_tool=tool_name,
            requirement=(
                f"Validate arguments against tool schema {tool.schema_version}; "
                f"required fields: {', '.join(required) or 'none'}."
            ),
            enforcement="deny",
            confidence=1.0,
        )
    ]
    for recommendation in recommendations:
        paths: list[str] = []
        condition = recommendation.rule.condition
        operands = [condition.left, condition.right]
        for operand in operands:
            if (
                operand is not None
                and operand.path is not None
                and not operand.path.startswith("action.")
            ):
                paths.append(operand.path)
        stage: Literal[
            "schema_validation",
            "trusted_context",
            "approval",
            "operation_binding",
            "version_control",
            "idempotency",
            "policy_decision",
            "execution",
        ] = (
            "approval"
            if "confirm" in recommendation.id or "approval" in recommendation.id
            else "operation_binding"
            if "operation-id" in recommendation.id
            else "version_control"
            if "expected-version" in recommendation.id
            else "idempotency"
            if "idempotency-key" in recommendation.id
            else "trusted_context"
            if recommendation.id.startswith("bind-")
            else "schema_validation"
        )
        gates.append(
            FunctionalGate(
                id=f"enforce-{recommendation.id}",
                stage=stage,
                target_tool=tool_name,
                requirement=recommendation.title,
                enforcement=(
                    "escalate" if recommendation.rule.decision == "escalate" else "deny"
                ),
                rule_ids=[recommendation.rule.id],
                trusted_context_paths=paths,
                confidence=recommendation.confidence,
            )
        )
    gates.extend(
        [
            FunctionalGate(
                id=f"evaluate-{tool_name.replace('_', '-')}-policy",
                stage="policy_decision",
                target_tool=tool_name,
                requirement=(
                    "Evaluate the generated policy at pre_tool_call with "
                    "server-resolved context."
                ),
                enforcement="deny",
                rule_ids=[item.rule.id for item in recommendations],
                confidence=1.0,
            ),
            FunctionalGate(
                id=f"execute-{tool_name.replace('_', '-')}-after-allow",
                stage="execution",
                target_tool=tool_name,
                requirement=("Invoke the tool only after an explicit allow decision."),
                enforcement="deny",
                confidence=1.0,
            ),
        ]
    )
    return gates


def propose_project_policies(
    project: ProjectDefinition,
) -> list[PolicyProposal]:
    proposals = []
    for tool in project.tools:
        if not (tool.risk == "consequential-write" or tool.mutates_state is True):
            continue
        recommendations = recommend_policies(project, tool.name)
        proposals.append(
            PolicyProposal(
                target_tool=tool.name,
                recommendations=recommendations,
                policy=synthesize_policy(
                    project,
                    tool.name,
                    recommendations,
                ),
                functional_gates=build_functional_gates(
                    project,
                    tool.name,
                    recommendations,
                ),
            )
        )
    return proposals


def synthesize_policy(
    project: ProjectDefinition,
    tool_name: str,
    recommendations: list[Recommendation] | None = None,
) -> CanonicalPolicy:
    selected = recommendations or recommend_policies(project, tool_name)
    rules = [item.rule for item in selected]
    guards = [
        complement(rule.condition)
        for rule in rules
        if rule.decision in {"deny", "escalate"}
    ]
    if guards:
        rules.append(
            PolicyRule(
                id="allow-valid-action",
                decision="allow",
                reason="all generated policy constraints passed",
                condition=Condition(operator="all", conditions=guards),
            )
        )
    tool = next(item for item in project.tools if item.name == tool_name)
    source_targets = []
    if tool.source_path is not None:
        source_targets.append(
            SourceReference(
                path=tool.source_path,
                line=tool.source_line,
                symbol=tool.handler or tool.name,
                role="tool_registration",
            )
        )
    return CanonicalPolicy(
        metadata=PolicyMetadata(
            name=f"{tool_name.replace('_', '-')}-policy",
            description=f"Generated policy for {tool_name}",
        ),
        tool=tool_name,
        tool_schema_version=tool.schema_version,
        source_targets=source_targets,
        rules=rules,
    )
