# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import re

from policy_authoring.domain.models import (
    CapabilityInventory,
    ControlAnalysis,
    ControlKind,
    ControlRequirement,
    DiscoveryReport,
    PolicyCoverage,
    ProjectDefinition,
    ToolDefinition,
)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _is_policy_candidate(tool: ToolDefinition) -> bool:
    return tool.mutates_state is True or tool.risk == "consequential-write"


def build_capability_inventory(
    discovery: DiscoveryReport,
) -> CapabilityInventory:
    tools = discovery.project.tools
    return CapabilityInventory(
        project=discovery.project.name,
        tools=tools,
        total_tools=len(tools),
        mutating_tools=sum(
            tool.mutates_state is True or tool.risk in {"write", "consequential-write"}
            for tool in tools
        ),
        approval_required_tools=sum(tool.requires_approval is True for tool in tools),
        unknown_tools=sum(tool.risk == "unknown" for tool in tools),
        evidence=discovery.evidence,
    )


def _context_path(
    project: ProjectDefinition,
    suffix: str,
) -> str | None:
    return next(
        (
            attribute.path
            for attribute in project.context.attributes
            if attribute.path.endswith(suffix)
            and attribute.trust not in {"model_provided", "untrusted"}
        ),
        None,
    )


def _requirement(
    tool: ToolDefinition,
    kind: ControlKind,
    requirement: str,
    *,
    project: ProjectDefinition,
    enforcement_point: str,
    context_suffix: str | None = None,
    always_proposed: bool = False,
) -> ControlRequirement:
    observation = next(
        (
            item
            for item in project.controls
            if item.target_tool == tool.name and item.kind == kind
        ),
        None,
    )
    context_path = (
        _context_path(project, context_suffix) if context_suffix is not None else None
    )
    if always_proposed:
        implementation_status = "proposed"
        confidence = 1.0
        evidence = ["Generated policy package must enforce this boundary."]
    elif observation is not None:
        implementation_status = "existing"
        confidence = observation.confidence
        evidence = [
            f"{observation.path}:{observation.line or 1}",
            observation.detail,
        ]
    elif context_path is not None:
        implementation_status = "proposed"
        confidence = 0.8
        evidence = [f"Trusted context is available at {context_path}."]
    else:
        implementation_status = "unknown"
        confidence = 0.5
        evidence = ["No implementation or trusted context evidence was found."]
    return ControlRequirement(
        id=f"{_slug(tool.name)}-{kind.replace('_', '-')}",
        target_tool=tool.name,
        kind=kind,
        requirement=requirement,
        implementation_status=implementation_status,  # type: ignore[arg-type]
        enforcement_point=enforcement_point,  # type: ignore[arg-type]
        evidence=evidence,
        context_paths=[context_path] if context_path is not None else [],
        confidence=confidence,
    )


def analyze_controls(discovery: DiscoveryReport) -> ControlAnalysis:
    project = discovery.project
    requirements: list[ControlRequirement] = []
    gaps: list[str] = []
    candidates = [tool for tool in project.tools if _is_policy_candidate(tool)]
    for tool in project.tools:
        requirements.append(
            _requirement(
                tool,
                "schema_validation",
                "Validate tool arguments against the discovered schema.",
                project=project,
                enforcement_point="schema",
                always_proposed=True,
            )
        )
        if not _is_policy_candidate(tool):
            continue
        requirements.extend(
            [
                _requirement(
                    tool,
                    "operation_binding",
                    "Bind the action to a host-provided workflow operation.",
                    project=project,
                    enforcement_point="host_runtime",
                    context_suffix=".operation_id",
                ),
                _requirement(
                    tool,
                    "version_check",
                    "Reject stale state before applying a mutation.",
                    project=project,
                    enforcement_point="tool",
                    context_suffix=".expected_version",
                ),
                _requirement(
                    tool,
                    "idempotency",
                    "Require a retry-safe idempotency key.",
                    project=project,
                    enforcement_point="tool",
                    context_suffix=".idempotency_key",
                ),
                _requirement(
                    tool,
                    "mutation_boundary",
                    "Route side effects through a single guarded mutation boundary.",
                    project=project,
                    enforcement_point="tool",
                ),
                _requirement(
                    tool,
                    "audit",
                    "Record the authorized mutation and actor.",
                    project=project,
                    enforcement_point="tool",
                ),
                _requirement(
                    tool,
                    "policy_decision",
                    "Evaluate policy immediately before the tool call.",
                    project=project,
                    enforcement_point="policy",
                    always_proposed=True,
                ),
                _requirement(
                    tool,
                    "execution",
                    "Execute only after an explicit allow decision.",
                    project=project,
                    enforcement_point="host_runtime",
                    always_proposed=True,
                ),
            ]
        )
        if tool.requires_approval is True:
            requirements.append(
                _requirement(
                    tool,
                    "approval_binding",
                    (
                        "Require a positive approval bound to the current "
                        "operation and action payload."
                    ),
                    project=project,
                    enforcement_point="host_runtime",
                    context_suffix=".approval.valid",
                )
            )

    for requirement in requirements:
        if requirement.implementation_status == "proposed":
            gaps.append(
                f"{requirement.target_tool}: proposed "
                f"{requirement.kind.replace('_', ' ')} control is not "
                "observed in source"
            )
        elif requirement.implementation_status == "unknown":
            gaps.append(
                f"{requirement.target_tool}: no evidence for "
                f"{requirement.kind.replace('_', ' ')}"
            )
    for tool in project.tools:
        if tool.risk == "unknown":
            gaps.append(f"{tool.name}: action impact is not classified")

    policies_with_rules = sum(
        bool(proposal.policy.rules) for proposal in discovery.proposals
    )
    return ControlAnalysis(
        project=project.name,
        requirements=requirements,
        coverage=PolicyCoverage(
            total_tools=len(project.tools),
            classified_tools=sum(tool.risk != "unknown" for tool in project.tools),
            mutating_tools=sum(
                tool.mutates_state is True
                or tool.risk in {"write", "consequential-write"}
                for tool in project.tools
            ),
            approval_required_tools=sum(
                tool.requires_approval is True for tool in project.tools
            ),
            policy_candidates=len(candidates),
            policies_generated=len(discovery.proposals),
            policies_with_rules=policies_with_rules,
            scenarios_generated=0,
        ),
        gaps=sorted(set(gaps)),
        review_questions=discovery.questions,
    )
