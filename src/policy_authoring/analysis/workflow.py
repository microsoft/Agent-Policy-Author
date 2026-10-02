# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from policy_authoring.analysis.service import (
    analyze_controls,
    build_capability_inventory,
)
from policy_authoring.discovery import discover_project
from policy_authoring.domain.input_validation import evaluate_effective_policy
from policy_authoring.domain.models import (
    ActionControlReport,
    PhaseOutcome,
    RunStatus,
    ToolEnforcementOutcome,
)
from policy_authoring.evaluation.cross_engine import (
    build_scenarios,
    evaluate_codebase,
)
from policy_authoring.ingestion.loader import dump_yaml
from policy_authoring.service import AuthoringService
from policy_authoring.storage.repository import Repository


def _write_json(path: Path, value: object) -> None:
    if isinstance(value, BaseModel):
        content = value.model_dump_json(indent=2)
    else:
        content = json.dumps(value, indent=2)
    path.write_text(content, encoding="utf-8")


def _overall_status(phases: list[PhaseOutcome]) -> RunStatus:
    statuses = {phase.status for phase in phases}
    if statuses.issubset({"passed", "not_applicable"}) and (
        "not_applicable" in statuses
    ):
        return "not_applicable"
    if statuses.intersection({"failed", "blocked"}):
        return "failed"
    if "needs_review" in statuses:
        return "needs_review"
    if statuses.intersection({"partial", "not_run"}):
        return "partial"
    return "passed"


def _markdown(report: ActionControlReport) -> str:
    lines = [
        "# Action-control analysis",
        "",
        f"- Project: `{report.project}`",
        f"- Overall status: `{report.overall_status}`",
        "",
        "## Outcomes",
        "",
        "| Outcome | Status | Detail |",
        "|---|---|---|",
    ]
    lines.extend(
        f"| {phase.phase} | {phase.status} | {phase.detail} |"
        for phase in report.phases
    )
    lines.extend(
        [
            "",
            "## Coverage",
            "",
            f"- Tools discovered: {report.inventory.total_tools}",
            f"- Mutating tools: {report.inventory.mutating_tools}",
            (f"- Approval-required tools: {report.inventory.approval_required_tools}"),
            (
                "- Policies with enforceable rules: "
                f"{report.control_analysis.coverage.policies_with_rules}"
            ),
            (
                "- Verification scenarios: "
                f"{report.control_analysis.coverage.scenarios_generated}"
            ),
            "",
            "## Enforcement",
            "",
            "| Tool | Rules | Scenarios | Compilation | Native | Status |",
            "|---|---:|---:|---|---|---|",
        ]
    )
    for outcome in report.enforcement:
        compiled = (
            "passed"
            if outcome.compilation and all(outcome.compilation.values())
            else "failed"
        )
        lines.append(
            f"| {outcome.target_tool} | {outcome.rule_count} | "
            f"{outcome.scenario_count} | {compiled} | "
            f"{outcome.native_verification} | {outcome.status} |"
        )
    return "\n".join(lines) + "\n"


def run_action_control_analysis(
    source: Path,
    output: Path,
    *,
    targets: list[str] | None = None,
    verify_native: bool = False,
    cerbos_image: str = "ghcr.io/cerbos/cerbos:0.46.0",
    cerbos_port: int = 13593,
) -> ActionControlReport:
    resolved_source = source.resolve(strict=True)
    allowed_root = (
        resolved_source if resolved_source.is_dir() else resolved_source.parent
    )
    destination = output.resolve()
    discover_directory = destination / "01-discover"
    identify_directory = destination / "02-identify"
    enforce_directory = destination / "03-enforce"
    for directory in (
        discover_directory,
        identify_directory,
        enforce_directory,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    discovery = discover_project(
        resolved_source,
        allowed_roots=(allowed_root,),
    )
    inventory = build_capability_inventory(discovery)
    control_analysis = analyze_controls(discovery)
    _write_json(discover_directory / "capability-inventory.json", inventory)
    _write_json(discover_directory / "discovery-report.json", discovery)
    (discover_directory / "project.yaml").write_text(
        dump_yaml(discovery.project),
        encoding="utf-8",
    )
    _write_json(
        identify_directory / "control-analysis.json",
        control_analysis,
    )

    requested_targets = targets or [
        "opa",
        "cedar",
        "cerbos",
        "agent-hooks",
        "acs",
    ]
    service = AuthoringService(
        Repository(enforce_directory / "analysis.db"),
        enforce_directory / "artifacts",
    )
    service.import_project(discovery.project)
    outcomes: list[ToolEnforcementOutcome] = []
    scenario_total = 0
    for index, proposal in enumerate(discovery.proposals):
        tool_directory = enforce_directory / proposal.target_tool
        tool_directory.mkdir(parents=True, exist_ok=True)
        (tool_directory / "policy.yaml").write_text(
            dump_yaml(proposal.policy),
            encoding="utf-8",
        )
        (tool_directory / "functional-gates.yaml").write_text(
            dump_yaml(
                {
                    "gates": [
                        gate.model_dump(mode="json")
                        for gate in proposal.functional_gates
                    ]
                }
            ),
            encoding="utf-8",
        )
        compile_targets = list(requested_targets)
        if "agent-hooks" in compile_targets and "opa" not in compile_targets:
            compile_targets.append("opa")
        compilations = service.compile_draft(
            discovery.project.name,
            proposal.policy,
            compile_targets,
        )
        compatibility = {item.target: item.compatible for item in compilations}
        scenarios = build_scenarios(
            discovery.project,
            proposal.target_tool,
            proposal.policy,
        )
        scenario_total += len(scenarios)
        _write_json(
            tool_directory / "scenarios.json",
            [scenario.model_dump(mode="json") for scenario in scenarios],
        )
        canonical_results = []
        for scenario in scenarios:
            decision = evaluate_effective_policy(
                discovery.project,
                proposal.target_tool,
                proposal.policy,
                scenario.context,
            )
            passed = decision.decision == scenario.expected_decision
            canonical_results.append(
                {
                    "scenario": scenario.id,
                    "expected": scenario.expected_decision,
                    "actual": decision.decision,
                    "matched_rule_ids": decision.matched_rule_ids,
                    "evaluation_stage": decision.evaluation_stage,
                    "policy_evaluated": decision.policy_evaluated,
                    "detail": decision.reason,
                    "passed": passed,
                }
            )
        _write_json(
            tool_directory / "canonical-verification.json",
            canonical_results,
        )
        native_status: RunStatus = "not_run"
        if verify_native:
            try:
                native_report = evaluate_codebase(
                    resolved_source,
                    tool_directory / "native",
                    tool_name=proposal.target_tool,
                    targets=requested_targets,
                    generate_only=False,
                    cerbos_image=cerbos_image,
                    cerbos_port=cerbos_port + index,
                )
                native_status = native_report.overall_status
            except (RuntimeError, ValueError) as exc:
                native_status = "failed"
                _write_json(
                    tool_directory / "native-error.json",
                    {
                        "tool": proposal.target_tool,
                        "status": "engine_error",
                        "detail": str(exc),
                    },
                )
        compile_ok = bool(requested_targets) and all(
            compatibility.get(target, False) for target in requested_targets
        )
        canonical_ok = bool(canonical_results) and all(
            item["passed"] for item in canonical_results
        )
        has_rules = bool(proposal.policy.rules)
        if not compile_ok or not canonical_ok or not has_rules:
            status: RunStatus = "failed"
        elif verify_native and native_status == "passed":
            status = "passed"
        elif verify_native:
            status = native_status
        else:
            status = "partial"
        outcomes.append(
            ToolEnforcementOutcome(
                target_tool=proposal.target_tool,
                status=status,
                rule_count=len(proposal.policy.rules),
                scenario_count=len(scenarios),
                canonical_cases_passed=sum(
                    item["passed"] is True for item in canonical_results
                ),
                canonical_cases_total=len(canonical_results),
                compilation={
                    target: compatibility.get(target, False)
                    for target in requested_targets
                },
                native_verification=native_status,
                artifact_directory=str(tool_directory),
            )
        )

    coverage = control_analysis.coverage.model_copy(
        update={"scenarios_generated": scenario_total}
    )
    control_analysis = control_analysis.model_copy(update={"coverage": coverage})
    _write_json(
        identify_directory / "control-analysis.json",
        control_analysis,
    )
    discover_status: RunStatus = "needs_review" if inventory.unknown_tools else "passed"
    existing_controls = sum(
        item.implementation_status == "existing"
        for item in control_analysis.requirements
    )
    proposed_controls = sum(
        item.implementation_status == "proposed"
        for item in control_analysis.requirements
    )
    missing_controls = sum(
        item.implementation_status == "unknown"
        for item in control_analysis.requirements
    )
    identify_status: RunStatus = (
        "not_applicable"
        if not discovery.project.tools
        else "needs_review"
        if control_analysis.review_questions or control_analysis.gaps
        else "passed"
    )
    if not discovery.project.tools:
        enforce_status: RunStatus = "not_applicable"
        enforce_detail = (
            "No agent tools were discovered, so no policy packages are needed."
        )
    elif not outcomes:
        enforce_status = "not_applicable"
        enforce_detail = (
            "No mutating actions were identified, so no enforcement packages "
            "are needed."
        )
    elif any(item.status == "failed" for item in outcomes):
        enforce_status = "failed"
        enforce_detail = "One or more policy packages failed verification."
    elif verify_native and all(item.status == "passed" for item in outcomes):
        enforce_status = "passed"
        enforce_detail = (
            f"Generated and natively verified {len(outcomes)} policy packages."
        )
    else:
        enforce_status = "partial"
        enforce_detail = (
            f"Generated and canonically verified {len(outcomes)} policy "
            "packages; native engine verification was not run."
        )
    phases = [
        PhaseOutcome(
            phase="discover",
            status=discover_status,
            detail=(
                "No supported agent tools were discovered."
                if not discovery.project.tools
                else f"Inventoried {inventory.total_tools} tools, including "
                f"{inventory.mutating_tools} mutating actions."
            ),
        ),
        PhaseOutcome(
            phase="identify",
            status=identify_status,
            detail=(
                "Control identification is not applicable without agent tools."
                if not discovery.project.tools
                else (
                    f"Existing {existing_controls}, proposed "
                    f"{proposed_controls}, missing {missing_controls}; "
                    f"{len(control_analysis.gaps)} require review."
                )
            ),
        ),
        PhaseOutcome(
            phase="enforce",
            status=enforce_status,
            detail=enforce_detail,
        ),
    ]
    report = ActionControlReport(
        project=discovery.project.name,
        source=str(resolved_source),
        phases=phases,
        inventory=inventory,
        control_analysis=control_analysis,
        enforcement=outcomes,
        overall_status=_overall_status(phases),
    )
    _write_json(destination / "action-control-report.json", report)
    (destination / "action-control-report.md").write_text(
        _markdown(report),
        encoding="utf-8",
    )
    return report
