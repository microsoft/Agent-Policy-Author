# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from pydantic import ValidationError

from policy_authoring import __version__
from policy_authoring.analysis import run_action_control_analysis
from policy_authoring.config import Settings
from policy_authoring.domain.models import (
    ActionControlReport,
    DiscoveryReport,
    FindingDisposition,
)
from policy_authoring.evaluation import evaluate_codebase
from policy_authoring.ingestion.loader import dump_yaml, load_policy, load_project
from policy_authoring.runtime import evaluate_current_opa
from policy_authoring.service import AuthoringService
from policy_authoring.storage.repository import Repository
from policy_authoring.workbench_app import run_workbench_tui
from policy_authoring.workspace import (
    approve_workspace,
    build_approval_packet,
    build_workbench_report,
    compile_workspace,
    export_policy_package,
    initialize_workspace,
    load_workspace_review,
    product_provenance,
    refresh_workspace,
    test_workspace,
    verify_publication_bundle,
)

app = typer.Typer(
    help="Author and compile portable policies for agentic pipelines.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


def _parse_finding_dispositions(
    values: list[str] | None,
    evidence_values: list[str] | None = None,
    expiry_values: list[str] | None = None,
    control_values: list[str] | None = None,
) -> list[FindingDisposition]:
    def keyed(values: list[str] | None, option: str) -> dict[str, list[str]]:
        parsed: dict[str, list[str]] = {}
        for value in values or []:
            try:
                finding_id, detail = value.split("=", 1)
            except ValueError as exc:
                raise typer.BadParameter(
                    f"{option} must use <finding-id>=<value>"
                ) from exc
            parsed.setdefault(finding_id, []).append(detail)
        return parsed

    evidence = keyed(evidence_values, "--finding-evidence")
    expiries = keyed(expiry_values, "--finding-expiry")
    controls = keyed(control_values, "--compensating-control")
    dispositions: list[FindingDisposition] = []
    for value in values or []:
        try:
            finding_id, remainder = value.split("=", 1)
            disposition, rationale = remainder.split(":", 1)
            dispositions.append(
                FindingDisposition.model_validate(
                    {
                        "finding_id": finding_id,
                        "disposition": disposition,
                        "rationale": rationale,
                        "evidence": evidence.get(finding_id, []),
                        "expires_at": (
                            expiries[finding_id][0] if finding_id in expiries else None
                        ),
                        "compensating_controls": controls.get(
                            finding_id,
                            [],
                        ),
                    }
                )
            )
        except (ValueError, ValidationError) as exc:
            raise typer.BadParameter(
                "finding dispositions must use "
                "<finding-id>=<resolved|accepted_risk|false_positive>:<rationale>"
            ) from exc
    return dispositions


def _finding_options(
    finding_disposition: list[str] | None,
    finding_evidence: list[str] | None,
    finding_expiry: list[str] | None,
    compensating_control: list[str] | None,
) -> list[FindingDisposition]:
    return _parse_finding_dispositions(
        finding_disposition,
        finding_evidence,
        finding_expiry,
        compensating_control,
    )


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = False,
) -> None:
    del version


def _service() -> AuthoringService:
    settings = Settings.from_environment()
    return AuthoringService(
        Repository(settings.data_dir / "policy-authoring.db"),
        settings.artifact_dir,
    )


def _error(message: str) -> NoReturn:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, bold=True, err=True)
    raise typer.Exit(code=2)


_STATUS_COLORS = {
    "passed": typer.colors.GREEN,
    "approved": typer.colors.GREEN,
    "partial": typer.colors.YELLOW,
    "needs_review": typer.colors.YELLOW,
    "needs_reconciliation": typer.colors.RED,
    "stale": typer.colors.RED,
    "not_run": typer.colors.YELLOW,
    "failed": typer.colors.RED,
    "blocked": typer.colors.RED,
    "rejected": typer.colors.RED,
    "not_applicable": typer.colors.BRIGHT_BLACK,
}


def _styled_status(status: str, width: int = 0) -> str:
    value = status.upper()
    if width:
        value = f"{value:<{width}}"
    return typer.style(
        value,
        fg=_STATUS_COLORS.get(status, typer.colors.WHITE),
        bold=True,
    )


def _phase_line(name: str, status: str, detail: str) -> None:
    label = typer.style(
        f"{name.upper():<10}",
        fg=typer.colors.CYAN,
        bold=True,
    )
    state = _styled_status(status, 15)
    typer.echo(f"{label} {state} {detail}")


def _metric(label: str, value: int) -> None:
    styled_label = typer.style(
        f"{label:<27}",
        fg=typer.colors.BRIGHT_BLACK,
    )
    styled_value = typer.style(
        str(value),
        fg=typer.colors.WHITE,
        bold=True,
    )
    typer.echo(f"{styled_label}{styled_value}")


def _artifact_paths(report_path: Path, destination: Path) -> None:
    typer.echo()
    typer.echo(
        f"{typer.style('Report:', fg=typer.colors.BRIGHT_BLACK)}    "
        f"{typer.style(str(report_path), fg=typer.colors.BLUE, bold=True)}"
    )
    typer.echo(
        f"{typer.style('Artifacts:', fg=typer.colors.BRIGHT_BLACK)} "
        f"{typer.style(str(destination), fg=typer.colors.BLUE)}"
    )


def _prompt_choice(
    prompt: str,
    choices: dict[str, str],
    *,
    render_choices: bool = True,
) -> str:
    rendered = ", ".join(f"{key}={label}" for key, label in choices.items())
    while True:
        label = f"{prompt} [{rendered}]" if render_choices else prompt
        value = str(typer.prompt(label)).strip().lower()
        if value in choices:
            return value
        typer.secho(
            f"Choose one of: {', '.join(choices)}",
            fg=typer.colors.YELLOW,
        )


def _section(title: str) -> None:
    typer.echo()
    typer.secho(f"== {title} " + "=" * max(2, 68 - len(title)), fg=typer.colors.CYAN)


def _prompt_menu(title: str, choices: dict[str, str]) -> str:
    _section(title)
    for key, label in choices.items():
        typer.echo(
            f"  {typer.style(f'[{key}]', fg=typer.colors.CYAN, bold=True)} "
            f"{label}"
        )
    return _prompt_choice(
        f"Select [{'/'.join(choices)}]",
        choices,
        render_choices=False,
    )


def _select_policy(report: dict[str, Any]) -> dict[str, Any] | None:
    policies = report.get("policies", [])
    if not policies:
        typer.echo("No policy candidates are available.")
        return None
    if len(policies) == 1:
        return dict(policies[0])
    typer.echo()
    typer.secho("SELECT POLICY", fg=typer.colors.CYAN, bold=True)
    choices: dict[str, str] = {}
    for index, policy in enumerate(policies, start=1):
        key = str(index)
        choices[key] = str(policy["tool"])
        status = _styled_status(str(policy["status"]))
        typer.echo(f"  {key:>2}. {policy['tool']:<32} {status}")
    choices["b"] = "back"
    selected = _prompt_choice(
        f"Select policy [1-{len(policies)}, b=back]",
        choices,
        render_choices=False,
    )
    if selected == "b":
        return None
    return dict(policies[int(selected) - 1])


def _approval_requirement_label(value: object) -> str:
    if value is True:
        return "required by source declaration"
    if value is False:
        return "not required by source declaration"
    return "source declaration absent; workspace review required"


def _show_text_artifact(title: str, path: Path) -> None:
    _section(title)
    typer.secho(str(path), fg=typer.colors.BRIGHT_BLACK)
    try:
        typer.echo(path.read_text(encoding="utf-8").rstrip())
    except (OSError, UnicodeDecodeError) as exc:
        typer.secho(
            f"Could not read {path}: {exc}",
            fg=typer.colors.RED,
            bold=True,
        )


def _show_policy_details(
    workspace: Path,
    report: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    policy = policy or _select_policy(report)
    if policy is None:
        return None
    tool = str(policy["tool"])
    _section(f"POLICY REVIEW - {tool}")
    typer.echo(f"Status: {policy['status']}")
    typer.echo(
        f"Risk: {policy['risk']}; "
        f"{_approval_requirement_label(policy['requires_approval'])}"
    )
    source = policy.get("source")
    if isinstance(source, dict):
        location = str(source.get("path", "unknown"))
        if source.get("line") is not None:
            location += f":{source['line']}"
        typer.echo(f"Source: {location}")
    tests = policy["tests"]
    typer.echo(f"Tests: {tests['passed']}/{tests['total']} passed")
    unresolved = policy.get("unresolved_findings", policy["blocking_findings"])
    if unresolved:
        typer.secho("Blocking findings:", fg=typer.colors.RED, bold=True)
        for finding in unresolved:
            typer.echo(f"  - {finding}")
    if policy["questions"]:
        typer.secho("Review questions:", fg=typer.colors.YELLOW, bold=True)
        for question in policy["questions"]:
            typer.echo(f"  - {question}")
    policy_path = workspace / "policies" / f"{tool}.yaml"
    test_path = workspace / "tests" / f"{tool}.yaml"
    _show_text_artifact("POLICY YAML", policy_path)
    _show_text_artifact("POLICY TESTS", test_path)
    typer.echo()
    typer.secho(
        "Review the policy rules and test expectations shown above before approval.",
        fg=typer.colors.YELLOW,
    )
    return policy


def _open_workspace_file(
    workspace: Path,
    report: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> None:
    policy = policy or _select_policy(report)
    if policy is None:
        return
    tool = str(policy["tool"])
    artifact = _prompt_choice(
        "Artifact",
        {
            "p": "policy",
            "t": "tests",
            "c": "trusted context",
            "b": "back",
        },
    )
    if artifact == "b":
        return
    selected = {
        "p": workspace / "policies" / f"{tool}.yaml",
        "t": workspace / "tests" / f"{tool}.yaml",
        "c": workspace / "context.yaml",
    }[artifact]
    action = _prompt_choice(
        "Inspect",
        {
            "v": "view in terminal",
            "o": "open in associated editor",
            "b": "back",
        },
    )
    if action == "b":
        return
    if action == "v":
        typer.echo()
        typer.secho(str(selected), fg=typer.colors.CYAN, bold=True)
        try:
            typer.echo(selected.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            typer.secho(
                f"Could not read {selected}: {exc}",
                fg=typer.colors.RED,
                bold=True,
            )
        return
    typer.echo(f"Opening {selected} in the associated editor.")
    try:
        launched = typer.launch(str(selected))
    except OSError as exc:
        typer.secho(
            f"Could not open {selected}: {exc}",
            fg=typer.colors.RED,
            bold=True,
        )
        return
    if launched != 0:
        typer.secho(
            f"The associated editor did not open successfully: {selected}",
            fg=typer.colors.RED,
            bold=True,
        )


def _split_prompt_values(prompt: str) -> list[str]:
    value = typer.prompt(prompt, default="", show_default=False).strip()
    return [item.strip() for item in value.split(",") if item.strip()]


def _collect_finding_dispositions(
    packet: dict[str, Any],
) -> list[FindingDisposition] | None:
    finding_ids = sorted(
        {
            str(finding)
            for policy in packet["policies"]
            for finding in policy["blocking_findings"]
        }
    )
    dispositions: list[FindingDisposition] = []
    for finding_id in finding_ids:
        typer.echo()
        typer.secho(
            f"Blocking finding: {finding_id}",
            fg=typer.colors.RED,
            bold=True,
        )
        choice = _prompt_choice(
            "Disposition",
            {
                "a": "accept risk",
                "f": "mark false positive",
                "b": "cancel approval",
            },
        )
        if choice == "b":
            return None
        rationale = typer.prompt(
            "Rationale (at least 12 characters)",
        ).strip()
        evidence = _split_prompt_values(
            "Evidence references (comma-separated)"
        )
        values: dict[str, Any] = {
            "finding_id": finding_id,
            "disposition": "accepted_risk" if choice == "a" else "false_positive",
            "rationale": rationale,
            "evidence": evidence,
        }
        if choice == "a":
            values["expires_at"] = typer.prompt(
                "Expiry (future ISO 8601 timestamp, for example "
                "2027-12-31T23:59:59Z)"
            ).strip()
            values["compensating_controls"] = _split_prompt_values(
                "Compensating controls (comma-separated)"
            )
        try:
            dispositions.append(FindingDisposition.model_validate(values))
        except ValidationError as exc:
            typer.secho(
                f"Invalid disposition: {exc}",
                fg=typer.colors.RED,
                bold=True,
            )
            return None
    return dispositions


def _interactive_approve(workspace: Path, tool_name: str) -> bool:
    try:
        initial_packet = build_approval_packet(workspace, tool_name=tool_name)
    except ValueError as exc:
        typer.secho(f"Approval is blocked: {exc}", fg=typer.colors.RED, bold=True)
        return False
    _section(f"REVIEW EVIDENCE - {tool_name}")
    typer.echo(f"Packet: {workspace / 'approval-packet.json'}")
    typer.echo(f"Policy: {tool_name}")
    typer.echo(f"Targets: {', '.join(initial_packet['targets'])}")
    typer.echo(f"Source revision: {initial_packet['source_revision']}")
    context_attributes = initial_packet["context"].get("attributes", [])
    typer.echo(f"Trusted context attributes: {len(context_attributes)}")
    for policy in initial_packet["policies"]:
        test_result = policy.get("test_result")
        test_status = (
            "passing"
            if isinstance(test_result, dict) and test_result.get("passed")
            else "missing or failing"
        )
        typer.echo(
            f"  {policy['tool']}: default={policy['default_decision']}; "
            f"{len(policy['rules'])} rules; tests={test_status}"
        )
        for rule in policy["rules"]:
            typer.echo(
                f"    Rule: {rule['id']} -> {rule['decision']} "
                f"({rule['reason']})"
            )
        for case in policy["tests"]:
            typer.echo(
                f"    Test: {case['id']} -> {case['expected_decision']}"
            )
        for finding in policy["blocking_findings"]:
            typer.secho(f"    Blocking: {finding}", fg=typer.colors.RED)
        for target, fidelity in policy["target_fidelity"].items():
            compatibility = fidelity.get("compatibility", [])
            lossy = sum(
                item.get("fidelity") == "lossy_fail_closed"
                for item in compatibility
                if isinstance(item, dict)
            )
            typer.echo(
                f"    Target: {target}; compatible={fidelity['compatible']}; "
                f"lossy fail-closed rules={lossy}"
            )
    provenance = product_provenance()
    if provenance["dirty"] is True:
        typer.secho(
            "Warning: this product build has dirty source provenance and cannot "
            "create a release-grade local bundle without explicit acknowledgement.",
            fg=typer.colors.YELLOW,
            bold=True,
        )
    dispositions = _collect_finding_dispositions(initial_packet)
    if dispositions is None:
        typer.echo("Approval cancelled.")
        return False
    acknowledgements: list[str] = []
    for acknowledgement in initial_packet["required_semantic_acknowledgements"]:
        typer.echo()
        typer.secho(
            f"Lossy fail-closed translation: {acknowledgement}",
            fg=typer.colors.YELLOW,
            bold=True,
        )
        if not typer.confirm(
            "Acknowledge this target-specific semantic difference?",
            default=False,
        ):
            typer.echo("Approval cancelled.")
            return False
        acknowledgements.append(str(acknowledgement))
    try:
        packet = build_approval_packet(
            workspace,
            tool_name=tool_name,
            finding_dispositions=dispositions,
            semantic_acknowledgements=acknowledgements,
        )
    except ValueError as exc:
        typer.secho(f"Approval is blocked: {exc}", fg=typer.colors.RED, bold=True)
        return False
    typer.echo(f"Confirmation digest: {packet['confirmation_digest']}")
    typer.echo("The complete evidence packet is available at:")
    typer.echo(f"  {workspace / 'approval-packet.json'}")
    if not typer.confirm(
        "Approve this exact policy, test, source, and finding snapshot?",
        default=False,
    ):
        typer.echo("Approval cancelled.")
        return False
    reviewer = typer.prompt("Reviewer identity").strip()
    reviewer_role = typer.prompt(
        "Reviewer role or team",
        default="",
        show_default=False,
    ).strip()
    rationale = typer.prompt("Approval rationale").strip()
    try:
        count = approve_workspace(
            workspace,
            tool_name=tool_name,
            reviewer=reviewer,
            rationale=rationale,
            reviewer_role=reviewer_role or None,
            finding_dispositions=dispositions,
            approval_packet_digest=str(packet["confirmation_digest"]),
            semantic_acknowledgements=acknowledgements,
        )
    except ValueError as exc:
        typer.secho(f"Approval failed: {exc}", fg=typer.colors.RED, bold=True)
        return False
    typer.secho(
        f"Approved {count} {'policy' if count == 1 else 'policies'}.",
        fg=typer.colors.GREEN,
        bold=True,
    )
    return True


def _edit_policy(workspace: Path, tool_name: str) -> bool:
    policy_path = workspace / "policies" / f"{tool_name}.yaml"
    try:
        original_policy = policy_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        typer.secho(
            f"Could not read {policy_path}: {exc}",
            fg=typer.colors.RED,
            bold=True,
        )
        return False
    _section(f"EDIT POLICY - {tool_name}")
    typer.echo("Opening the selected policy in its associated editor:")
    typer.secho(str(policy_path), fg=typer.colors.BLUE, bold=True)
    launched = False
    try:
        launched = typer.launch(str(policy_path)) == 0
    except OSError as exc:
        typer.secho(
            f"Automatic editor launch failed: {exc}",
            fg=typer.colors.YELLOW,
        )
    if not launched:
        typer.secho(
            "Automatic editor launch was unavailable. Edit this file manually, "
            "then return here:",
            fg=typer.colors.YELLOW,
            bold=True,
        )
        typer.secho(str(policy_path), fg=typer.colors.BLUE, bold=True)
        prompt = "After saving the policy, press Enter to validate and rerun tests"
    else:
        prompt = "Save the policy, then press Enter to validate and rerun tests"
    try:
        typer.prompt(
            prompt,
            default="",
            show_default=False,
        )
        while True:
            try:
                load_policy(policy_path)
                break
            except ValueError as exc:
                typer.secho(
                    f"Policy validation failed: {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                )
                action = typer.prompt(
                    "Fix and save the policy, then press Enter to retry; "
                    "enter b to discard the edit",
                    default="",
                    show_default=False,
                )
                if action.strip().lower() == "b":
                    policy_path.write_text(original_policy, encoding="utf-8")
                    typer.secho(
                        "Invalid policy edit discarded; the last valid policy "
                        "was restored.",
                        fg=typer.colors.YELLOW,
                        bold=True,
                    )
                    return False
    except (typer.Abort, EOFError):
        policy_path.write_text(original_policy, encoding="utf-8")
        raise
    typer.secho(
        "Policy schema is valid. Revalidating the workspace and tests...",
        fg=typer.colors.GREEN,
        bold=True,
    )
    return True


def _review_policy_flow(
    workspace: Path,
    report: dict[str, Any],
) -> str:
    policy = _select_policy(report)
    if policy is None:
        return "none"
    _show_policy_details(workspace, report, policy)
    tool_name = str(policy["tool"])
    choices = {
        "m": "modify this policy",
        "e": "browse or open related evidence",
        "b": "back to workbench",
    }
    if policy["status"] != "approved":
        choices = {
            "a": "review evidence and approve this policy",
            **choices,
        }
    while True:
        action = _prompt_menu(f"{tool_name} actions", choices)
        if action == "b":
            return "none"
        if action == "m":
            return "edited" if _edit_policy(workspace, tool_name) else "none"
        if action == "e":
            _open_workspace_file(workspace, report, policy)
        elif action == "a":
            return (
                "approved"
                if _interactive_approve(workspace, tool_name)
                else "none"
            )


def _interactive_compile(workspace: Path) -> bool:
    provenance = product_provenance()
    allow_dirty_product = False
    if provenance["packaged"] and provenance["dirty"] is True:
        typer.secho(
            "DIRTY PRODUCT BUILD",
            fg=typer.colors.YELLOW,
            bold=True,
        )
        typer.echo(
            "This installed wheel was built from uncommitted product changes. "
            "Its commit does not fully identify the running implementation."
        )
        if not typer.confirm(
            "Create a local bundle with dirty provenance acknowledged?",
            default=False,
        ):
            typer.echo(
                "Compilation cancelled. Rebuild the package from a clean commit "
                "for release-grade provenance."
            )
            return False
        allow_dirty_product = True
    if not typer.confirm(
        "Compile and promote an immutable bundle in this local workspace?",
        default=True,
    ):
        return False
    require_validated = typer.confirm(
        "Require declared validation assurance for every target?",
        default=True,
    )
    require_exact = typer.confirm(
        "Require exact target semantics (reject fail-closed lossy rules)?",
        default=False,
    )
    try:
        report = compile_workspace(
            workspace,
            require_validated=require_validated,
            require_exact_semantics=require_exact,
            allow_dirty_product=allow_dirty_product,
        )
    except (ValueError, RuntimeError) as exc:
        typer.secho(f"Compilation failed: {exc}", fg=typer.colors.RED, bold=True)
        return False
    if report.get("promoted"):
        typer.secho("LOCAL BUNDLE PROMOTED", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"Bundle: {report['bundle']}")
        typer.echo(f"Digest: {report['bundle_digest']}")
        return True
    typer.secho("PUBLICATION NOT PROMOTED", fg=typer.colors.RED, bold=True)
    typer.echo(f"Failure report: {report.get('failure_report')}")
    return False


def _interactive_workbench(
    workspace: Path,
    report: dict[str, Any],
    run_tests: bool,
) -> None:
    while True:
        summary = report["summary"]
        _section("POLICY WORKBENCH")
        typer.echo(
            f"Readiness: {_styled_status(str(report['readiness']))}; "
            f"{summary['approved']}/{summary['policies']} approved; "
            f"{summary['blocking_findings']} blocking findings"
        )
        choices = {
            "r": "review a policy",
            "e": "browse policy evidence",
            "t": "run all policy tests",
        }
        if report["readiness"] == "needs_reconciliation":
            choices["s"] = "sync changed source inventory"
        if report["readiness"] == "passed":
            choices["c"] = "compile and promote local bundle"
        choices["q"] = "quit"
        action = _prompt_menu("ACTIONS", choices)
        if action == "q":
            typer.echo(f"Workspace saved at {workspace}")
            return
        if action == "r":
            result = _review_policy_flow(workspace, report)
            if result != "none":
                try:
                    report = build_workbench_report(
                        workspace,
                        run_tests=True if result == "edited" else run_tests,
                    )
                    if result == "edited":
                        typer.secho(
                            "Policy validated and workspace tests rerun. "
                            "Review the updated readiness before approval.",
                            fg=typer.colors.GREEN,
                            bold=True,
                        )
                except (ValueError, RuntimeError) as exc:
                    typer.secho(
                        f"Workbench failed: {exc}",
                        fg=typer.colors.RED,
                        bold=True,
                    )
                    return
        elif action == "e":
            _open_workspace_file(workspace, report)
            try:
                report = build_workbench_report(workspace, run_tests=run_tests)
            except (ValueError, RuntimeError) as exc:
                typer.secho(
                    f"Workbench failed: {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                )
                return
        elif action == "t":
            try:
                report = build_workbench_report(workspace, run_tests=True)
            except (ValueError, RuntimeError) as exc:
                typer.secho(f"Tests failed: {exc}", fg=typer.colors.RED, bold=True)
            else:
                passed = sum(
                    item["tests"]["status"] == "passed"
                    for item in report["policies"]
                )
                total = len(report["policies"])
                color = typer.colors.GREEN if passed == total else typer.colors.RED
                typer.secho(
                    f"Policy tests: {passed}/{total} policies passed.",
                    fg=color,
                    bold=True,
                )
        elif action == "s":
            if not typer.confirm(
                "Apply the discovered source changes and invalidate approvals?",
                default=False,
            ):
                continue
            try:
                refresh = refresh_workspace(workspace)
            except (ValueError, RuntimeError) as exc:
                typer.secho(f"Refresh failed: {exc}", fg=typer.colors.RED, bold=True)
            else:
                typer.secho(
                    (
                        "Workspace source inventory refreshed."
                        if refresh["applied"]
                        else "Workspace source inventory is already current."
                    ),
                    fg=typer.colors.GREEN,
                    bold=True,
                )
                try:
                    report = build_workbench_report(
                        workspace,
                        run_tests=run_tests,
                    )
                except (ValueError, RuntimeError) as exc:
                    typer.secho(
                        f"Workbench failed: {exc}",
                        fg=typer.colors.RED,
                        bold=True,
                    )
                    return
        elif action == "c":
            _interactive_compile(workspace)


def _analysis_summary(
    report: ActionControlReport,
    destination: Path,
) -> None:
    inventory = report.inventory
    coverage = report.control_analysis.coverage
    typer.secho(
        "ACTION CONTROL ANALYSIS",
        fg=typer.colors.CYAN,
        bold=True,
    )
    typer.echo()
    for phase in report.phases:
        _phase_line(phase.phase, phase.status, phase.detail)
    typer.echo()
    _metric("Tools discovered:", inventory.total_tools)
    _metric("Mutating actions:", inventory.mutating_tools)
    _metric(
        "Approval-required actions:",
        inventory.approval_required_tools,
    )
    _metric("Policies generated:", coverage.policies_generated)
    _metric("Verification scenarios:", coverage.scenarios_generated)
    _artifact_paths(
        destination / "action-control-report.md",
        destination,
    )


def _discovery_summary(
    report: DiscoveryReport,
    destination: Path,
) -> None:
    summary = report.summary
    typer.secho(
        "CAPABILITY DISCOVERY",
        fg=typer.colors.CYAN,
        bold=True,
    )
    typer.echo()
    _metric("Tools discovered:", summary.tools_discovered)
    _metric("Mutating actions:", summary.mutating_tools)
    _metric(
        "Approval-required actions:",
        summary.approval_required_tools,
    )
    _metric("Unknown classifications:", summary.unresolved_questions)
    _metric("Policy candidates:", summary.consequential_tools)
    _artifact_paths(destination / "discovery-report.json", destination)


@app.command("init")
def init_workspace_command(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            help="Source file or repository directory to author policy for.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            help="Policy workspace; defaults to SOURCE/.agent-policy.",
        ),
    ] = None,
    targets: Annotated[
        str,
        typer.Option(
            help="Comma-separated policy targets used by workspace compilation.",
        ),
    ] = "opa,agent-hooks,acs",
    allow_no_actions: Annotated[
        bool,
        typer.Option(
            "--allow-no-actions",
            help=(
                "Create an intentionally empty workspace when discovery finds "
                "no supported agent actions."
            ),
        ),
    ] = False,
) -> None:
    source = path.resolve()
    source_root = source if source.is_dir() else source.parent
    destination = (output or source_root / ".agent-policy").resolve()
    target_names = [item.strip() for item in targets.split(",") if item.strip()]
    try:
        review = initialize_workspace(
            source,
            destination,
            targets=target_names,
            allow_no_actions=allow_no_actions,
        )
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    policy_actions = [
        item for item in review.actions if item.review_status != "not_applicable"
    ]
    typer.secho(
        "POLICY WORKSPACE CREATED",
        fg=typer.colors.CYAN,
        bold=True,
    )
    typer.echo()
    _metric("Actions inventoried:", len(review.actions))
    _metric("Policies drafted:", len(policy_actions))
    _metric(
        "Policies needing review:",
        sum(item.review_status == "needs_review" for item in policy_actions),
    )
    _metric(
        "Review questions:",
        sum(len(item.questions) for item in review.actions),
    )
    _artifact_paths(destination / "review.yaml", destination)
    typer.echo()
    typer.echo(
        "Next: "
        + typer.style(
            f"policy-author review {destination}",
            fg=typer.colors.GREEN,
            bold=True,
        )
    )


@app.command()
def workbench(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            help=("Source repository, source file, or existing policy workspace."),
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            help="Policy workspace; defaults to SOURCE/.agent-policy.",
        ),
    ] = None,
    targets: Annotated[
        str,
        typer.Option(
            help="Targets used when a new workspace is initialized.",
        ),
    ] = "opa,agent-hooks,acs",
    run_tests: Annotated[
        bool,
        typer.Option(
            "--test/--no-test",
            help="Recompute canonical policy tests before reporting readiness.",
        ),
    ] = True,
    require_actions: Annotated[
        bool,
        typer.Option(
            "--require-actions/--allow-no-actions",
            help=(
                "Fail when discovery finds no policy-relevant actions; use "
                "--allow-no-actions for intentional empty analysis."
            ),
        ),
    ] = True,
    interactive: Annotated[
        bool | None,
        typer.Option(
            "--interactive/--no-interactive",
            help=(
                "Keep the workbench open for guided review, editing, testing, "
                "approval, and publication. Defaults to interactive in a TTY."
            ),
        ),
    ] = None,
    require_ready: Annotated[
        bool,
        typer.Option(
            "--require-ready",
            help=(
                "Exit unsuccessfully unless readiness is passed. Intended for "
                "CI together with --no-interactive."
            ),
        ),
    ] = False,
) -> None:
    requested = path.resolve()
    workspace_created = False
    if requested.is_dir() and (requested / "policy-author.yaml").is_file():
        if output is not None:
            _error("--output cannot be used when path is already a workspace")
        workspace = requested
    else:
        source_root = requested if requested.is_dir() else requested.parent
        workspace = (output or source_root / ".agent-policy").resolve()
        if not (workspace / "policy-author.yaml").is_file():
            target_names = [item.strip() for item in targets.split(",") if item.strip()]
            try:
                initialize_workspace(
                    requested,
                    workspace,
                    targets=target_names,
                    allow_no_actions=True,
                )
            except (ValueError, RuntimeError) as exc:
                _error(str(exc))
            workspace_created = True

    try:
        report = build_workbench_report(workspace, run_tests=run_tests)
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    report["workspace_created"] = workspace_created
    report_path = workspace / "workbench-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    use_interactive = (
        interactive
        if interactive is not None
        else sys.stdin.isatty() and sys.stdout.isatty()
    )
    if require_ready and use_interactive:
        _error("--require-ready must be used with --no-interactive")

    typer.secho("POLICY WORKBENCH", fg=typer.colors.CYAN, bold=True)
    typer.echo()
    _phase_line(
        "workspace",
        "passed",
        f"{'Created' if workspace_created else 'Reused'} {workspace}",
    )
    typer.echo(f"Source: {report['resolved_source']}")
    _phase_line(
        "tests",
        report["tests"]["status"],
        report["tests"]["error"]
        or (
            "Canonical tests were skipped."
            if report["tests"]["status"] == "not_run"
            else "Canonical policy behavior evaluated."
        ),
    )
    _phase_line(
        "readiness",
        report["readiness"],
        (
            "Policies are ready to compile."
            if report["readiness"] == "passed"
            else (
                "Source discovery changed; refresh and review the normalized "
                "inventory before continuing."
            )
            if report["readiness"] == "needs_reconciliation"
            else "Human review or policy changes are still required."
            if report["readiness"] == "needs_review"
            else "No policy candidates were discovered."
            if report["readiness"] == "not_applicable"
            else "Canonical tests were not run."
            if report["readiness"] == "not_run"
            else "Resolve failed or incomplete policy tests."
        ),
    )
    if use_interactive and not (
        report["readiness"] == "not_applicable" and require_actions
    ):
        try:
            run_workbench_tui(workspace, report, run_tests=run_tests)
        except (ValueError, RuntimeError) as exc:
            _error(str(exc))
        return

    if report["policies"]:
        typer.echo()
        typer.secho("POLICIES", fg=typer.colors.CYAN, bold=True)
    for item in report["policies"]:
        source = item["source"]
        location = (
            f"{source['path']}:{source['line']}"
            if source is not None and source.get("line") is not None
            else str(source["path"])
            if source is not None
            else "source reference not provided by input"
        )
        tests = item["tests"]
        detail = (
            f"{location}; {item['rule_count']} rules; "
            f"tests {tests['passed']}/{tests['total']}"
        )
        _phase_line(item["tool"], item["status"], detail)
        typer.echo(
            f"  Risk: {item['risk']}; "
            f"{_approval_requirement_label(item['requires_approval'])}"
        )
        unresolved = item.get(
            "unresolved_findings",
            item["blocking_findings"],
        )
        for finding in unresolved:
            typer.secho(
                f"  Blocking finding: {finding}",
                fg=typer.colors.RED,
            )
        for question in item["questions"]:
            typer.echo(f"  Review: {question}")
        typer.echo(f"  Next: {item['next_action']}")

    reconciliation = report.get("reconciliation", {})
    if reconciliation.get("required"):
        typer.echo()
        typer.secho(
            "DISCOVERY CHANGES",
            fg=typer.colors.RED,
            bold=True,
        )
        for change in reconciliation.get("changes", []):
            subject = change.get("tool") or change.get("path") or "workspace"
            fields = change.get("fields", [])
            detail = f" ({', '.join(fields)})" if fields else ""
            typer.echo(f"- {change['kind']}: {subject}{detail}")

    typer.echo()
    summary = report["summary"]
    _metric("Actions inventoried:", summary["actions"])
    _metric("Governed policies:", summary["policies"])
    supporting_actions = summary["actions"] - summary["policies"]
    if supporting_actions > 0:
        _metric("Supporting/non-policy actions:", supporting_actions)
    _metric("Current approvals:", summary["approved"])
    _metric("Policies needing review:", summary["needs_review"])
    _metric("Blocking findings:", summary["blocking_findings"])
    _artifact_paths(report_path, workspace)
    if report["next_commands"] and not use_interactive:
        typer.echo()
        typer.secho("NEXT COMMANDS", fg=typer.colors.CYAN, bold=True)
        for command in report["next_commands"]:
            typer.echo(f"  {command}")
    if report["warnings"]:
        typer.echo()
        typer.secho("WARNINGS", fg=typer.colors.YELLOW, bold=True)
        for warning in report["warnings"]:
            typer.echo(f"- {warning}")
    if report["readiness"] in {"failed", "needs_reconciliation"} or (
        report["readiness"] == "not_applicable" and require_actions
    ) or (require_ready and report["readiness"] != "passed"):
        raise typer.Exit(code=1)


@app.command("refresh-workspace")
def refresh_workspace_command(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
) -> None:
    try:
        report = refresh_workspace(workspace)
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    if not report["applied"]:
        typer.secho(
            "Workspace discovery is already current.",
            fg=typer.colors.GREEN,
            bold=True,
        )
        return
    typer.secho(
        "WORKSPACE DISCOVERY REFRESHED",
        fg=typer.colors.GREEN,
        bold=True,
    )
    for change in report["changes"]:
        subject = change.get("tool") or change.get("path") or "workspace"
        fields = change.get("fields", [])
        detail = f" ({', '.join(fields)})" if fields else ""
        typer.echo(f"- {change['kind']}: {subject}{detail}")
    if report["suggestions"]:
        typer.echo("Generated comparison policies:")
        for path in report["suggestions"]:
            typer.echo(f"  {path}")
    if report["retired"]:
        typer.echo("Retired artifacts:")
        for path in report["retired"]:
            typer.echo(f"  {path}")
    typer.echo(
        "Approvals were invalidated. Review policy, tests, context, and "
        "reconciliation suggestions before rerunning workbench."
    )


@app.command()
def review(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
) -> None:
    try:
        effective = build_workbench_report(workspace, run_tests=True)
        report = load_workspace_review(workspace)
    except ValueError as exc:
        _error(str(exc))
    if effective["readiness"] == "needs_reconciliation":
        typer.secho(
            "POLICY REVIEW - SOURCE RECONCILIATION REQUIRED",
            fg=typer.colors.RED,
            bold=True,
        )
        for change in effective["reconciliation"]["changes"]:
            subject = change.get("tool") or change.get("path") or "workspace"
            fields = change.get("fields", [])
            detail = f" ({', '.join(fields)})" if fields else ""
            typer.echo(f"- {change['kind']}: {subject}{detail}")
        typer.echo(f"Next: policy-author refresh-workspace \"{workspace.resolve()}\"")
        raise typer.Exit(code=1)
    try:
        packet = build_approval_packet(workspace)
    except ValueError as exc:
        _error(str(exc))
    typer.secho("POLICY REVIEW", fg=typer.colors.CYAN, bold=True)
    typer.echo()
    effective_by_tool = {
        item["tool"]: item for item in effective.get("policies", [])
    }
    actionable = [
        item for item in report.actions if item.review_status != "not_applicable"
    ]
    for item in actionable:
        source = item.source_targets[0] if item.source_targets else None
        location = (
            f"{source.path}:{source.line}"
            if source is not None and source.line is not None
            else source.path
            if source is not None
            else "source reference not provided by input"
        )
        _phase_line(
            item.tool,
            str(
                effective_by_tool.get(item.tool, {}).get(
                    "status",
                    "needs_review",
                )
            ),
            location,
        )
        packet_policy = next(
            value for value in packet["policies"] if value["tool"] == item.tool
        )
        typer.echo(f"  Policy: {packet_policy['policy_path']}")
        typer.echo(f"  Tests: {packet_policy['test_path']}")
        typer.echo(
            f"  Default: {packet_policy['default_decision']}; "
            f"rules: {len(packet_policy['rules'])}"
        )
        test_result = packet_policy.get("test_result")
        typer.echo(
            "  Test evidence: "
            + (
                "passing"
                if isinstance(test_result, dict) and test_result.get("passed")
                else "missing or failing"
            )
        )
        for question in item.questions:
            typer.echo(f"  - {question}")
        if item.approval is not None:
            typer.echo(
                f"  Approved by {item.approval.reviewer} at {item.approval.approved_at}"
            )
            for disposition in item.approval.finding_dispositions:
                typer.echo(
                    "  Finding disposition: "
                    f"{disposition.finding_id}={disposition.disposition} "
                    f"({disposition.rationale})"
                )
    typer.echo()
    _metric("Policies:", len(actionable))
    _metric(
        "Approved:",
        sum(
            effective_by_tool.get(item.tool, {}).get("status") == "approved"
            for item in actionable
        ),
    )
    _metric(
        "Needs review:",
        sum(
            effective_by_tool.get(item.tool, {}).get("status") != "approved"
            for item in actionable
        ),
    )
    if report.warnings:
        typer.echo()
        typer.secho("Warnings", fg=typer.colors.YELLOW, bold=True)
        for warning in report.warnings:
            typer.echo(f"- {warning}")
    typer.echo()
    typer.echo(f"Targets: {', '.join(packet['targets'])}")
    typer.echo(f"Context: {workspace.resolve() / 'context.yaml'}")
    typer.echo(f"Approval packet: {workspace.resolve() / 'approval-packet.json'}")
    approved_digests = {
        item.tool: item.approval.approval_packet_digest
        for item in actionable
        if item.approval is not None
    }
    if approved_digests:
        typer.echo("Approved packet digests:")
        for tool_name, digest in approved_digests.items():
            typer.echo(f"  {tool_name}: {digest}")
    typer.echo(
        f"Prospective confirmation snapshot: {packet['confirmation_digest']}"
    )


@app.command("approval-preview")
def approval_preview(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
    tool: Annotated[str, typer.Option(help="Tool to preview, or 'all'.")] = "all",
    finding_disposition: Annotated[
        list[str] | None,
        typer.Option("--finding-disposition"),
    ] = None,
    finding_evidence: Annotated[
        list[str] | None,
        typer.Option(
            "--finding-evidence",
            help="Repeat using FINDING_ID=EVIDENCE_REFERENCE.",
        ),
    ] = None,
    finding_expiry: Annotated[
        list[str] | None,
        typer.Option(
            "--finding-expiry",
            help="Use FINDING_ID=ISO_8601_TIMESTAMP.",
        ),
    ] = None,
    compensating_control: Annotated[
        list[str] | None,
        typer.Option(
            "--compensating-control",
            help="Repeat using FINDING_ID=CONTROL.",
        ),
    ] = None,
    acknowledge_lossy: Annotated[
        list[str] | None,
        typer.Option(
            "--acknowledge-lossy",
            help="Repeat using TARGET:RULE_ID from the approval packet.",
        ),
    ] = None,
) -> None:
    try:
        packet = build_approval_packet(
            workspace,
            tool_name=tool,
            finding_dispositions=_finding_options(
                finding_disposition,
                finding_evidence,
                finding_expiry,
                compensating_control,
            ),
            semantic_acknowledgements=acknowledge_lossy,
        )
    except ValueError as exc:
        _error(str(exc))
    typer.secho("APPROVAL PACKET READY", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"Packet: {workspace.resolve() / 'approval-packet.json'}")
    typer.echo(f"Policies: {len(packet['policies'])}")
    typer.echo(f"Targets: {', '.join(packet['targets'])}")
    required = packet["required_semantic_acknowledgements"]
    if required:
        typer.echo("Required semantic acknowledgements:")
        for acknowledgement in required:
            typer.echo(
                f"  --acknowledge-lossy {acknowledgement}"
            )
        typer.echo(
            "Use the same --acknowledge-lossy flags for approval-preview "
            "and approve because they are bound into the packet digest."
        )
    typer.echo(f"Confirm snapshot: {packet['confirmation_digest']}")


@app.command()
def approve(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
    tool: Annotated[
        str,
        typer.Option(help="Tool to approve, or 'all'."),
    ] = "all",
    reviewer: Annotated[
        str | None,
        typer.Option(help="Identity of the person approving the policy."),
    ] = None,
    rationale: Annotated[
        str | None,
        typer.Option(help="Reason the reviewed policy is being approved."),
    ] = None,
    reviewer_role: Annotated[
        str | None,
        typer.Option(help="Optional reviewer role or team."),
    ] = None,
    finding_disposition: Annotated[
        list[str] | None,
        typer.Option(
            "--finding-disposition",
            help=(
                "Repeat for each blocking finding using "
                "ID=STATUS:RATIONALE, where STATUS is accepted_risk "
                "or false_positive. "
                "Remediated findings must disappear on rediscovery."
            ),
        ),
    ] = None,
    finding_evidence: Annotated[
        list[str] | None,
        typer.Option(
            "--finding-evidence",
            help="Repeat using FINDING_ID=EVIDENCE_REFERENCE.",
        ),
    ] = None,
    finding_expiry: Annotated[
        list[str] | None,
        typer.Option(
            "--finding-expiry",
            help="Use FINDING_ID=ISO_8601_TIMESTAMP.",
        ),
    ] = None,
    compensating_control: Annotated[
        list[str] | None,
        typer.Option(
            "--compensating-control",
            help="Repeat using FINDING_ID=CONTROL.",
        ),
    ] = None,
    confirm_snapshot: Annotated[
        str | None,
        typer.Option(
            "--confirm-snapshot",
            help="Confirmation digest printed by approval-preview.",
        ),
    ] = None,
    acknowledge_lossy: Annotated[
        list[str] | None,
        typer.Option(
            "--acknowledge-lossy",
            help="Repeat using TARGET:RULE_ID from the approval packet.",
        ),
    ] = None,
    packet: Annotated[
        Path | None,
        typer.Option(
            "--packet",
            exists=True,
            dir_okay=False,
            help=(
                "Reuse finding dispositions and semantic acknowledgements "
                "from an approval-preview packet."
            ),
        ),
    ] = None,
) -> None:
    if not reviewer:
        _error("--reviewer is required")
    if not rationale:
        _error("--rationale is required")
    try:
        if packet is not None:
            if any(
                (
                    finding_disposition,
                    finding_evidence,
                    finding_expiry,
                    compensating_control,
                    acknowledge_lossy,
                )
            ):
                _error(
                    "--packet cannot be combined with finding or semantic "
                    "acknowledgement flags"
                )
            try:
                packet_document = json.loads(packet.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                _error(f"{packet}: invalid approval packet: {exc}")
            if Path(str(packet_document.get("workspace", ""))).resolve() != (
                workspace.resolve()
            ):
                _error("approval packet belongs to a different workspace")
            dispositions = [
                FindingDisposition.model_validate(item)
                for policy in packet_document.get("policies", [])
                for item in policy.get("proposed_dispositions", [])
            ]
            acknowledge_lossy = list(
                packet_document.get(
                    "proposed_semantic_acknowledgements",
                    [],
                )
            )
        else:
            dispositions = _finding_options(
                finding_disposition,
                finding_evidence,
                finding_expiry,
                compensating_control,
            )
        if not confirm_snapshot:
            preview_packet = build_approval_packet(
                workspace,
                tool_name=tool,
                finding_dispositions=dispositions,
                semantic_acknowledgements=acknowledge_lossy,
            )
            _error(
                "review approval-packet.json and rerun with "
                f"--confirm-snapshot {preview_packet['confirmation_digest']}"
            )
        count = approve_workspace(
            workspace,
            tool_name=tool,
            reviewer=reviewer,
            rationale=rationale,
            reviewer_role=reviewer_role,
            finding_dispositions=dispositions,
            approval_packet_digest=confirm_snapshot,
            semantic_acknowledgements=acknowledge_lossy,
        )
    except ValueError as exc:
        _error(str(exc))
    typer.secho(
        f"Approved {count} {'policy' if count == 1 else 'policies'}.",
        fg=typer.colors.GREEN,
        bold=True,
    )


@app.command("test-workspace")
def test_workspace_command(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
) -> None:
    try:
        report = test_workspace(workspace)
    except ValueError as exc:
        _error(str(exc))
    typer.secho("POLICY TESTS", fg=typer.colors.CYAN, bold=True)
    typer.echo()
    for item in report["results"]:
        _phase_line(
            item["tool"],
            "passed" if item["passed"] else "failed",
            f"{sum(case['passed'] for case in item['cases'])}/"
            f"{len(item['cases'])} cases passed",
        )
        for case in item["cases"]:
            if case["passed"]:
                continue
            typer.echo(
                f"  Failed {case['id']}: expected {case['expected']}, "
                f"actual {case['actual']}; matched rules: "
                f"{', '.join(case['matched_rule_ids']) or 'none'}"
            )
    typer.echo()
    _metric("Policies tested:", report["policies"])
    if not report["passed"]:
        raise typer.Exit(code=1)


@app.command("compile-workspace")
def compile_workspace_command(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ] = Path(".agent-policy"),
    targets: Annotated[
        str | None,
        typer.Option(help="Override workspace target engines."),
    ] = None,
    require_validated: Annotated[
        bool,
        typer.Option(
            "--require-validated",
            help=(
                "Require every selected target to satisfy its declared "
                "validation assurance before promotion."
            ),
        ),
    ] = False,
    require_exact_semantics: Annotated[
        bool,
        typer.Option(
            "--require-exact-semantics",
            help="Reject fail-closed lossy target translations.",
        ),
    ] = False,
    allow_dirty_product: Annotated[
        bool,
        typer.Option(
            "--allow-dirty-product",
            help=(
                "Acknowledge and allow a packaged build created from "
                "uncommitted product source."
            ),
        ),
    ] = False,
) -> None:
    selected = (
        [item.strip() for item in targets.split(",") if item.strip()]
        if targets
        else None
    )
    try:
        report = compile_workspace(
            workspace,
            targets=selected,
            require_validated=require_validated,
            require_exact_semantics=require_exact_semantics,
            allow_dirty_product=allow_dirty_product,
        )
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.secho("POLICY COMPILATION", fg=typer.colors.CYAN, bold=True)
    typer.echo()
    for item in report["policies"]:
        target_summary = ", ".join(
            f"{target}={outcome['validation']}"
            f"[{outcome.get('assurance') or 'none'}]"
            for target, outcome in item["targets"].items()
        )
        validations = [outcome["validation"] for outcome in item["targets"].values()]
        _phase_line(
            item["tool"],
            (
                "passed"
                if validations and all(status == "validated" for status in validations)
                else "partial"
                if validations and all(status != "failed" for status in validations)
                else "failed"
            ),
            target_summary,
        )
        for target, outcome in item["targets"].items():
            if outcome["validation"] != "failed":
                continue
            typer.secho(
                f"  {target}: {outcome['detail']}",
                fg=typer.colors.RED,
            )
    typer.echo()
    generated = workspace.resolve() / "generated"
    typer.echo()
    typer.echo(f"Profile: {report['publication_profile']}")
    typer.echo(f"Source: {report['resolved_source']}")
    typer.echo(
        "Declared target assurance: "
        + ("complete" if report["verified"] else "incomplete")
    )
    assurance = report.get("assurance_summary", {})
    typer.echo(
        "Assurance mix: "
        + (
            ", ".join(f"{kind}={count}" for kind, count in assurance.items())
            if assurance
            else "none"
        )
    )
    typer.echo(
        "Native validation for every target: "
        + ("yes" if report.get("native_validation_complete") else "no")
    )
    if report.get("promoted"):
        typer.secho("LOCAL BUNDLE PROMOTED", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"Bundle: {report['bundle']}")
        typer.echo(f"Digest: {report['bundle_digest']}")
        _artifact_paths(generated / "compilation-report.json", generated)
    else:
        typer.secho("LOCAL BUNDLE NOT PROMOTED", fg=typer.colors.RED, bold=True)
        if report.get("preserved_current_bundle"):
            typer.echo(
                f"Preserved current bundle: {report['preserved_current_bundle']}"
            )
        typer.echo(f"Failure report: {report.get('failure_report')}")
    if not report["compatible"]:
        raise typer.Exit(code=1)


@app.command("verify-bundle")
def verify_bundle_command(
    bundle: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ],
    require_validated: Annotated[
        bool,
        typer.Option(
            "--require-validated",
            help="Fail when any target lacks completed validation.",
        ),
    ] = False,
) -> None:
    try:
        result = verify_publication_bundle(
            bundle,
            require_validated=require_validated,
        )
    except ValueError as exc:
        _error(str(exc))
    typer.secho("BUNDLE INTEGRITY VERIFIED", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Digest: {result['bundle_digest']}")
    typer.echo(f"Artifacts: {result['artifacts']}")
    typer.echo(f"Profile: {result['publication_profile']}")
    typer.echo(
        "Declared target assurance: "
        + ("complete" if result["fully_validated"] else "incomplete")
    )
    assurance = result.get("assurance_summary", {})
    typer.echo(
        "Assurance mix: "
        + (
            ", ".join(f"{kind}={count}" for kind, count in assurance.items())
            if assurance
            else "none"
        )
    )
    typer.echo(
        "Native validation for every target: "
        + ("yes" if result["native_validation_complete"] else "no")
    )


@app.command("export-policy")
def export_policy_command(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ],
    tool: Annotated[str, typer.Argument(help="Policy tool name to export.")],
    target: Annotated[
        str,
        typer.Option(
            "--target",
            help=(
                "Target package: opa, cedar, cerbos, agent-hooks, or acs "
                "(Microsoft Agent Governance Toolkit)."
            ),
        ),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination ZIP path."),
    ],
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Replace an existing destination ZIP.",
        ),
    ] = False,
) -> None:
    try:
        result = export_policy_package(
            workspace,
            tool_name=tool,
            target=target,
            destination=output,
            overwrite=overwrite,
        )
    except (OSError, ValueError) as exc:
        _error(str(exc))
    typer.secho("POLICY PACKAGE EXPORTED", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Tool: {result['tool']}")
    typer.echo(f"Target: {result['target']}")
    typer.echo(f"Bundle: {result['bundle_digest']}")
    typer.echo(f"ZIP: {result['archive']}")


@app.command("evaluate-current")
def evaluate_current_command(
    workspace: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False),
    ],
    tool: Annotated[str, typer.Argument()],
    context: Annotated[
        Path,
        typer.Option(
            "--context",
            exists=True,
            dir_okay=False,
            help="Trusted canonical context JSON.",
        ),
    ],
) -> None:
    try:
        value = json.loads(context.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("context must contain a JSON object")
        decision = evaluate_current_opa(workspace, tool, value)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(json.dumps(decision, indent=2))


@app.command()
def analyze(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            help="Source file or repository directory to analyze.",
        ),
    ],
    targets: Annotated[
        str,
        typer.Option(
            help=("Comma-separated adapters: opa, cedar, cerbos, agent-hooks, acs.")
        ),
    ] = "opa,cedar,cerbos,agent-hooks,acs",
    verify_native: Annotated[
        bool,
        typer.Option(
            "--verify-native/--no-verify-native",
            help="Run installed native policy engines after generation.",
        ),
    ] = False,
    output: Annotated[
        Path,
        typer.Option(help="Directory for the three outcome artifacts."),
    ] = Path(".action-control"),
    cerbos_image: Annotated[
        str,
        typer.Option(help="Cerbos container image used for native evaluation."),
    ] = "ghcr.io/cerbos/cerbos:0.46.0",
    cerbos_port: Annotated[
        int,
        typer.Option(min=1, max=65535),
    ] = 13593,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Print the complete machine-readable report to stdout.",
        ),
    ] = False,
) -> None:
    target_names = [item.strip() for item in targets.split(",") if item.strip()]
    try:
        report = run_action_control_analysis(
            path,
            output,
            targets=target_names,
            verify_native=verify_native,
            cerbos_image=cerbos_image,
            cerbos_port=cerbos_port,
        )
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    destination = output.resolve()
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _analysis_summary(report, destination)
    if report.overall_status in {"failed", "blocked"}:
        raise typer.Exit(code=1)


@app.command("import-project")
def import_project(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    try:
        project = load_project(path)
        _service().import_project(project)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(f"Imported project {project.name}")


@app.command()
def discover(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    output: Annotated[
        Path | None,
        typer.Option(help="Output directory; defaults to PATH/.policy-authoring"),
    ] = None,
    import_project: Annotated[
        bool,
        typer.Option("--import/--no-import"),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Print the complete machine-readable report to stdout.",
        ),
    ] = False,
) -> None:
    root = path.resolve()
    try:
        report = _service().discover(
            root,
            allowed_roots=(root,),
            import_project=import_project,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    destination = (output or root / ".policy-authoring").resolve()
    if destination != root and not destination.is_relative_to(root):
        raise typer.BadParameter("output must be inside the discovered project")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "project.yaml").write_text(
        dump_yaml(report.project),
        encoding="utf-8",
    )
    (destination / "context-contract.yaml").write_text(
        dump_yaml(report.project.context),
        encoding="utf-8",
    )
    policy_directory = destination / "proposed-policies"
    policy_directory.mkdir(parents=True, exist_ok=True)
    for proposal in report.proposals:
        (policy_directory / f"{proposal.target_tool}.yaml").write_text(
            dump_yaml(proposal.policy),
            encoding="utf-8",
        )
    (destination / "functional-gates.yaml").write_text(
        dump_yaml(
            {
                "gates": [
                    gate.model_dump(mode="json")
                    for proposal in report.proposals
                    for gate in proposal.functional_gates
                ]
            }
        ),
        encoding="utf-8",
    )
    (destination / "discovery-report.json").write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    (destination / "unresolved-questions.yaml").write_text(
        dump_yaml(
            {"questions": [item.model_dump(mode="json") for item in report.questions]}
        ),
        encoding="utf-8",
    )
    with (destination / "normalized-traces.jsonl").open(
        "w",
        encoding="utf-8",
    ) as handle:
        for trace in report.project.traces:
            handle.write(trace.model_dump_json())
            handle.write("\n")
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _discovery_summary(report, destination)


@app.command()
def recommend(
    project: str,
    tool: str | None = typer.Option(None),
) -> None:
    try:
        recommendations = _service().recommendations(project, tool)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(
        dump_yaml(
            {
                "recommendations": [
                    item.model_dump(mode="json") for item in recommendations
                ]
            }
        )
    )


@app.command()
def synthesize(
    project: str,
    tool: str,
    output: Annotated[Path, typer.Option()] = Path("policy.yaml"),
) -> None:
    try:
        policy = _service().synthesize(project, tool)
        output.write_text(dump_yaml(policy), encoding="utf-8")
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(f"Wrote {output}")


@app.command("test")
def test_command(
    policy_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False),
    ],
    context_path: Annotated[
        Path,
        typer.Option("--context", exists=True, dir_okay=False),
    ],
) -> None:
    try:
        policy = load_policy(policy_path)
        context = json.loads(context_path.read_text(encoding="utf-8"))
        results = _service().test_policy(policy, context)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(json.dumps(results, indent=2))
    if not all(item["passed"] for item in results):
        raise typer.Exit(code=1)


def _compile_draft(
    project: str,
    policy_path: Path,
    targets: str,
) -> None:
    try:
        policy = load_policy(policy_path)
        names = [item.strip() for item in targets.split(",") if item.strip()]
        results = _service().compile_draft(project, policy, names)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(
        "Draft artifacts are unapproved and must not be published. "
        "Use compile-workspace for reviewed output.",
        err=True,
    )
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in results],
            indent=2,
        )
    )
    if not all(item.compatible for item in results):
        raise typer.Exit(code=1)


@app.command("compile-draft")
def compile_draft(
    project: str,
    policy_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False),
    ],
    targets: str = typer.Option(
        "agent-hooks,opa,cedar,cerbos,acs",
        help="Comma-separated target names.",
    ),
) -> None:
    _compile_draft(project, policy_path, targets)


@app.command("compile", hidden=True, deprecated=True)
def compile_legacy(
    project: str,
    policy_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False),
    ],
    targets: str = typer.Option(
        "agent-hooks,opa,cedar,cerbos,acs",
        help="Comma-separated target names.",
    ),
) -> None:
    typer.echo(
        "The compile command is deprecated and produces unapproved draft "
        "artifacts. Use compile-draft instead.",
        err=True,
    )
    _compile_draft(project, policy_path, targets)


@app.command("evaluate-engines")
def evaluate_engines(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            help="Source file or repository directory to analyze.",
        ),
    ],
    tool: Annotated[str | None, typer.Option()] = None,
    targets: Annotated[
        str,
        typer.Option(
            help=("Comma-separated adapters: opa, cedar, cerbos, agent-hooks, acs.")
        ),
    ] = "opa,cedar,cerbos,agent-hooks,acs",
    generate_only: Annotated[
        bool,
        typer.Option(
            "--generate-only",
            help=("Generate policy artifacts without invoking native engines."),
        ),
    ] = False,
    output: Annotated[
        Path,
        typer.Option(help="Directory for artifacts and the parity report."),
    ] = Path(".policy-evaluation"),
    cerbos_image: Annotated[
        str,
        typer.Option(help="Cerbos container image used for native evaluation."),
    ] = "ghcr.io/cerbos/cerbos:0.46.0",
    cerbos_port: Annotated[
        int,
        typer.Option(min=1, max=65535),
    ] = 13593,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Print the complete machine-readable report to stdout.",
        ),
    ] = False,
) -> None:
    target_names = [item.strip() for item in targets.split(",") if item.strip()]
    try:
        if tool is None:
            action_report = run_action_control_analysis(
                path,
                output,
                targets=target_names,
                verify_native=not generate_only,
                cerbos_image=cerbos_image,
                cerbos_port=cerbos_port,
            )
            destination = output.resolve()
            if json_output:
                typer.echo(action_report.model_dump_json(indent=2))
            else:
                _analysis_summary(action_report, destination)
            if action_report.overall_status in {"failed", "blocked"}:
                raise typer.Exit(code=1)
            return
        engine_report = evaluate_codebase(
            path,
            output,
            tool_name=tool,
            targets=target_names,
            generate_only=generate_only,
            cerbos_image=cerbos_image,
            cerbos_port=cerbos_port,
        )
    except (ValueError, RuntimeError) as exc:
        _error(str(exc))
    if json_output:
        typer.echo(engine_report.model_dump_json(indent=2))
    else:
        typer.secho(
            "CROSS-ENGINE EVALUATION",
            fg=typer.colors.CYAN,
            bold=True,
        )
        typer.echo()
        typer.echo(
            f"{typer.style('Tool:', fg=typer.colors.BRIGHT_BLACK)}        "
            f"{typer.style(engine_report.target_tool, bold=True)}"
        )
        _phase_line(
            "compile",
            engine_report.compilation_status,
            "Generated target policy artifacts.",
        )
        _phase_line(
            "verify",
            engine_report.evaluation_status,
            "Evaluated generated scenarios.",
        )
        _phase_line(
            "overall",
            engine_report.overall_status,
            "Cross-engine result.",
        )
        _artifact_paths(
            output.resolve() / "evaluation-report.md",
            output.resolve(),
        )
    if not engine_report.all_passed and not generate_only:
        raise typer.Exit(code=1)


@app.command()
def feedback(
    project: str,
    policy: str,
    label: Annotated[
        str,
        typer.Option(help="For example: false_positive or false_negative"),
    ],
    detail: Annotated[str, typer.Option()],
    rule: Annotated[str | None, typer.Option()] = None,
) -> None:
    try:
        service = _service()
        identifier = service.repository.save_feedback(
            project,
            policy,
            label,
            detail,
            rule,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(f"Recorded feedback {identifier}")


@app.command()
def tune(project: str, policy: str) -> None:
    try:
        suggestions = _service().tuning_suggestions(project, policy)
    except (OSError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    typer.echo(json.dumps(suggestions, indent=2))
