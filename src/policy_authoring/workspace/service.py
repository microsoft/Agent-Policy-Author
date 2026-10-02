# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import yaml
from pydantic import ValidationError

from policy_authoring import __version__
from policy_authoring.adapters.registry import default_registry
from policy_authoring.discovery import (
    SUPPORTED_DISCOVERY_SUFFIXES,
    discover_project,
)
from policy_authoring.domain.evaluator import evaluate_policy
from policy_authoring.domain.models import (
    ActionReview,
    ApprovalEvidence,
    CanonicalPolicy,
    ContextContract,
    FindingDisposition,
    PolicyTestCase,
    PolicyWorkspaceConfig,
    PolicyWorkspaceReview,
    ProjectDefinition,
    SourceReference,
    ToolDefinition,
)
from policy_authoring.domain.validation import (
    require_unique_test_ids,
    require_valid_policy,
)
from policy_authoring.ingestion.loader import (
    dump_yaml,
    format_validation_error,
    load_policy,
    load_project,
)
from policy_authoring.testing.generator import (
    build_synthetic_context,
    generate_tests,
)
from policy_authoring.workspace.validation import validate_target


def _write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_yaml(_jsonable(value)), encoding="utf-8")


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _read_mapping(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        problem = getattr(exc, "problem_mark", None)
        location = (
            f":{problem.line + 1}:{problem.column + 1}" if problem is not None else ""
        )
        raise ValueError(f"{path}{location}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _json_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _bundle_identity_payload(value: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = json.loads(json.dumps(value))
    policies = normalized.get("validation", {}).get("policies", [])
    for policy in policies:
        targets = policy.get("targets", {})
        for outcome in targets.values():
            validator = outcome.get("validator")
            if isinstance(validator, dict):
                validator.pop("started_at", None)
                validator.pop("completed_at", None)
    return normalized


def _policy_digest(path: Path) -> str:
    policy = load_policy(path)
    payload = policy.model_dump(mode="json")
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("review_status", None)
    return _json_digest(payload)


def _load_effective_project(root: Path) -> ProjectDefinition:
    project = load_project(root / "project.yaml")
    context_path = root / "context.yaml"
    try:
        context = ContextContract.model_validate(_read_mapping(context_path))
    except ValidationError as exc:
        raise ValueError(
            f"invalid context definition {context_path}: "
            f"{format_validation_error(exc)}"
        ) from exc
    return project.model_copy(update={"context": context})


def _adapter_identities(targets: list[str]) -> dict[str, str]:
    registry = default_registry()
    return {target: registry.get(target).identity for target in sorted(set(targets))}


def _findings_digest(
    action: ActionReview,
    dispositions: list[FindingDisposition],
) -> str:
    return _json_digest(
        {
            "blocking_findings": sorted(action.blocking_findings),
            "dispositions": [
                _canonical_disposition_payload(item)
                for item in sorted(
                    dispositions,
                    key=lambda value: value.finding_id,
                )
            ],
        }
    )


def _canonical_disposition_payload(
    disposition: FindingDisposition,
) -> dict[str, Any]:
    payload = disposition.model_dump(mode="json", exclude={"owner"})
    payload["evidence"] = sorted(disposition.evidence)
    payload["compensating_controls"] = sorted(disposition.compensating_controls)
    return payload


def _approval_dispositions_current(approval: ApprovalEvidence) -> bool:
    now = datetime.now(UTC)
    return all(
        item.disposition != "accepted_risk"
        or (
            item.expires_at is not None
            and item.expires_at.tzinfo is not None
            and item.expires_at > now
        )
        for item in approval.finding_dispositions
    )


def _snapshot_digest(
    *,
    source_revision: str,
    project_digest: str,
    context_digest: str,
    workspace_config_digest: str,
    policy_digest: str,
    test_digest: str,
    test_result_digest: str,
    findings_digest: str,
    targets: list[str],
    adapter_identities: dict[str, str],
) -> str:
    return _json_digest(
        {
            "product_version": __version__,
            "source_revision": source_revision,
            "project_digest": project_digest,
            "context_digest": context_digest,
            "workspace_config_digest": workspace_config_digest,
            "policy_digest": policy_digest,
            "test_digest": test_digest,
            "test_result_digest": test_result_digest,
            "findings_digest": findings_digest,
            "targets": sorted(targets),
            "adapter_identities": adapter_identities,
        }
    )


def _approval_snapshot(
    root: Path,
    config: PolicyWorkspaceConfig,
    action: ActionReview,
    test_result: dict[str, Any],
    dispositions: list[FindingDisposition],
    *,
    source_revision: str,
    targets: list[str],
) -> dict[str, Any]:
    policy_path = root / config.policy_directory / f"{action.tool}.yaml"
    test_path = root / config.test_directory / f"{action.tool}.yaml"
    adapter_identities = _adapter_identities(targets)
    snapshot: dict[str, Any] = {
        "source_revision": source_revision,
        "policy_digest": _policy_digest(policy_path),
        "test_digest": _file_digest(test_path),
        "test_result_digest": _json_digest(test_result),
        "project_digest": _file_digest(root / "project.yaml"),
        "context_digest": _file_digest(root / "context.yaml"),
        "workspace_config_digest": _file_digest(root / "policy-author.yaml"),
        "findings_digest": _findings_digest(action, dispositions),
        "adapter_identities": adapter_identities,
        "product_version": __version__,
        "targets": list(targets),
    }
    snapshot["snapshot_digest"] = _snapshot_digest(
        source_revision=source_revision,
        project_digest=str(snapshot["project_digest"]),
        context_digest=str(snapshot["context_digest"]),
        workspace_config_digest=str(snapshot["workspace_config_digest"]),
        policy_digest=str(snapshot["policy_digest"]),
        test_digest=str(snapshot["test_digest"]),
        test_result_digest=str(snapshot["test_result_digest"]),
        findings_digest=str(snapshot["findings_digest"]),
        targets=targets,
        adapter_identities=adapter_identities,
    )
    return snapshot


def _approval_stale_fields(
    approval: ApprovalEvidence,
    snapshot: dict[str, Any],
) -> list[str]:
    checks = {
        "source": approval.source_revision == snapshot["source_revision"],
        "policy": approval.policy_digest == snapshot["policy_digest"],
        "tests": approval.test_digest == snapshot["test_digest"],
        "test results": (
            approval.test_result_digest == snapshot["test_result_digest"]
        ),
        "project": approval.project_digest == snapshot["project_digest"],
        "context": approval.context_digest == snapshot["context_digest"],
        "workspace configuration": (
            approval.workspace_config_digest == snapshot["workspace_config_digest"]
        ),
        "findings": approval.findings_digest == snapshot["findings_digest"],
        "adapter identities": (
            approval.adapter_identities == snapshot["adapter_identities"]
        ),
        "targets": approval.targets == snapshot["targets"],
        "product version": approval.product_version == snapshot["product_version"],
        "snapshot": approval.snapshot_digest == snapshot["snapshot_digest"],
    }
    return [name for name, current in checks.items() if not current]


def _tree_digest(root: Path, excluded_root: Path) -> str:
    digest = hashlib.sha256()
    supported = {*SUPPORTED_DISCOVERY_SUFFIXES, ".toml"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in supported:
            continue
        if path.is_relative_to(excluded_root):
            continue
        relative = path.relative_to(root)
        if any(
            part.startswith(".") or part == "__pycache__" for part in relative.parts
        ):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _source_revision(
    config: PolicyWorkspaceConfig,
    workspace_root: Path,
) -> str:
    source = _resolve_workspace_source(config, workspace_root)
    repository = source if source.is_dir() else source.parent
    completed = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    commit = completed.stdout.strip() if completed.returncode == 0 else "unversioned"
    return f"{commit}:{_tree_digest(repository, workspace_root)}"


def _resolve_workspace_source(
    config: PolicyWorkspaceConfig,
    workspace_root: Path,
) -> Path:
    configured = Path(config.source_root)
    if config.source_mode == "workspace_relative":
        if configured.is_absolute():
            raise ValueError("workspace-relative source_root must not be absolute")
        return (workspace_root / configured).resolve(strict=True)
    if not configured.is_absolute():
        raise ValueError("external source_root must be absolute")
    return configured.resolve(strict=True)


def _workspace_root(path: Path) -> Path:
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("policy workspace must be a directory")
    if not (root / "policy-author.yaml").is_file():
        raise ValueError(
            f"{root} is not a policy workspace; run policy-author init first"
        )
    return root


def _project_reconciliation(
    current: ProjectDefinition,
    discovered: ProjectDefinition,
) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []
    current_tools = {tool.name: tool for tool in current.tools}
    discovered_tools = {tool.name: tool for tool in discovered.tools}
    for name in sorted(discovered_tools.keys() - current_tools.keys()):
        changes.append({"kind": "tool_added", "tool": name})
    for name in sorted(current_tools.keys() - discovered_tools.keys()):
        changes.append({"kind": "tool_removed", "tool": name})
    compared_fields = (
        "description",
        "risk",
        "input_schema",
        "mutates_state",
        "requires_approval",
        "domain",
        "handler",
        "source_path",
        "source_line",
        "metadata_source",
    )
    for name in sorted(current_tools.keys() & discovered_tools.keys()):
        before = current_tools[name].model_dump(mode="json")
        after = discovered_tools[name].model_dump(mode="json")
        fields = [
            field for field in compared_fields if before.get(field) != after.get(field)
        ]
        if fields:
            changes.append(
                {
                    "kind": "tool_changed",
                    "tool": name,
                    "fields": fields,
                    "before": {field: before.get(field) for field in fields},
                    "after": {field: after.get(field) for field in fields},
                }
            )
    current_context = {
        item.path: item.model_dump(mode="json") for item in current.context.attributes
    }
    discovered_context = {
        item.path: item.model_dump(mode="json")
        for item in discovered.context.attributes
    }
    for path in sorted(discovered_context.keys() - current_context.keys()):
        changes.append({"kind": "context_added", "path": path})
    for path in sorted(current_context.keys() - discovered_context.keys()):
        changes.append({"kind": "context_removed", "path": path})
    for path in sorted(current_context.keys() & discovered_context.keys()):
        if current_context[path] != discovered_context[path]:
            changes.append({"kind": "context_changed", "path": path})
    for label, previous_items, discovered_items in (
        (
            "traces",
            [item.model_dump(mode="json") for item in current.traces],
            [item.model_dump(mode="json") for item in discovered.traces],
        ),
        (
            "controls",
            [item.model_dump(mode="json") for item in current.controls],
            [item.model_dump(mode="json") for item in discovered.controls],
        ),
    ):
        if previous_items != discovered_items:
            changes.append(
                {
                    "kind": f"{label}_changed",
                    "before_digest": _json_digest(previous_items),
                    "after_digest": _json_digest(discovered_items),
                }
            )
    if current.name != discovered.name:
        changes.append(
            {
                "kind": "project_changed",
                "field": "name",
                "before": current.name,
                "after": discovered.name,
            }
        )
    return {
        "required": bool(changes),
        "changes": changes,
        "current_digest": _json_digest(current.model_dump(mode="json")),
        "discovered_digest": _json_digest(discovered.model_dump(mode="json")),
    }


def _discover_workspace_source(
    root: Path,
    config: PolicyWorkspaceConfig,
) -> tuple[Any, dict[str, Any]]:
    source = _resolve_workspace_source(config, root)
    allowed_root = source if source.is_dir() else source.parent
    discovery = discover_project(source, allowed_roots=(allowed_root,))
    current = load_project(root / "project.yaml")
    return discovery, _project_reconciliation(current, discovery.project)


def _write_reconciliation_report(
    root: Path,
    report: dict[str, Any],
) -> None:
    path = root / "discovery-reconciliation.json"
    if report["required"]:
        _write_json_atomic(path, report)
    elif path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            path.unlink()
        else:
            if not existing.get("applied"):
                path.unlink()


def _reconciliation_obligations(
    root: Path,
    config: PolicyWorkspaceConfig,
) -> dict[str, list[str]]:
    path = root / "discovery-reconciliation.json"
    if not path.is_file():
        return {}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    obligations = report.get("obligations", [])
    if not isinstance(obligations, list):
        return {}
    active: dict[str, list[str]] = {}
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        identifier = obligation.get("id")
        tool = obligation.get("tool")
        required_rule_ids = obligation.get("required_rule_ids")
        requires_disposition = obligation.get("requires_disposition") is True
        if (
            not isinstance(identifier, str)
            or not isinstance(tool, str)
            or not isinstance(required_rule_ids, list)
            or not all(isinstance(item, str) for item in required_rule_ids)
        ):
            continue
        policy_path = root / config.policy_directory / f"{tool}.yaml"
        if requires_disposition:
            active.setdefault(tool, []).append(identifier)
            continue
        if not policy_path.is_file():
            active.setdefault(tool, []).append(identifier)
            continue
        policy_rule_ids = {rule.id for rule in load_policy(policy_path).rules}
        if not set(required_rule_ids).issubset(policy_rule_ids):
            active.setdefault(tool, []).append(identifier)
    return active


def _effective_action_review(
    root: Path,
    config: PolicyWorkspaceConfig,
    action: ActionReview,
) -> ActionReview:
    active = _reconciliation_obligations(root, config).get(action.tool, [])
    findings = set(action.blocking_findings) | set(active)
    questions = list(action.questions)
    policy_path = root / config.policy_directory / f"{action.tool}.yaml"
    if "incomplete_policy_synthesis" in findings and policy_path.is_file():
        policy = load_policy(policy_path)
        if policy.rules:
            findings.remove("incomplete_policy_synthesis")
            questions = [
                question
                for question in questions
                if not question.startswith("No enforceable rules were synthesized.")
            ]
    return action.model_copy(
        update={
            "blocking_findings": sorted(findings),
            "questions": questions,
        }
    )


def _ensure_no_unclassified_actions(review: PolicyWorkspaceReview) -> None:
    unknown = sorted(
        action.tool for action in review.actions if action.risk == "unknown"
    )
    if unknown:
        raise ValueError(
            "unclassified action risk blocks readiness; classify these tools in "
            f"the source or project definition and refresh the workspace: "
            f"{', '.join(unknown)}"
        )


def _ensure_discovery_reconciled(
    root: Path,
    config: PolicyWorkspaceConfig,
) -> None:
    _, report = _discover_workspace_source(root, config)
    _write_reconciliation_report(root, report)
    if report["required"]:
        raise ValueError(
            "workspace discovery is stale; run policy-author refresh-workspace "
            f"{root} and review discovery-reconciliation.json before testing, "
            "approval, or compilation"
        )


def _source_targets(tool: ToolDefinition) -> list[SourceReference]:
    if tool.source_path is None:
        return []
    return [
        SourceReference(
            path=tool.source_path,
            line=tool.source_line,
            symbol=tool.handler or tool.name,
            role="tool_registration",
        )
    ]


def _review_for_tool(
    tool: ToolDefinition,
    proposal_rule_ids: list[str],
    observed_controls: set[str],
) -> ActionReview:
    policy_candidate = tool.mutates_state is True or tool.risk == "consequential-write"
    questions = []
    blocking_findings = []
    if policy_candidate:
        questions.append(
            "Confirm that the generated rules match the intended authorization "
            "behavior for this action."
        )
        if not proposal_rule_ids:
            blocking_findings.append("incomplete_policy_synthesis")
            questions.append(
                "No enforceable rules were synthesized. Author a coherent "
                "policy with at least one explicit decision rule before approval."
            )
    if tool.requires_approval is True:
        if "approval_binding" not in observed_controls:
            blocking_findings.append("missing_reachable_approval_check")
            questions.append(
                "Declared intent requires approval, but static analysis did not "
                "find a reachable approval check. Review the generated policy "
                "and author the missing host approval integration."
            )
        questions.append(
            "Confirm the approval evidence, operation binding, payload binding, "
            "and expiry requirements."
        )
    if tool.risk == "unknown":
        blocking_findings.append("unclassified_action_risk")
        questions.append(
            "Classify whether this action reads data, changes local state, or "
            "causes a consequential external effect."
        )
    return ActionReview(
        tool=tool.name,
        risk=tool.risk,
        mutates_state=tool.mutates_state,
        requires_approval=tool.requires_approval,
        review_status=(
            "needs_review"
            if policy_candidate or tool.risk == "unknown"
            else "not_applicable"
        ),
        source_targets=_source_targets(tool),
        proposed_rule_ids=proposal_rule_ids,
        questions=questions,
        blocking_findings=blocking_findings,
    )


def initialize_workspace(
    source: Path,
    output: Path,
    *,
    targets: list[str] | None = None,
    allow_no_actions: bool = False,
) -> PolicyWorkspaceReview:
    resolved_source = source.resolve(strict=True)
    allowed_root = (
        resolved_source if resolved_source.is_dir() else resolved_source.parent
    )
    destination = output.resolve()
    if (destination / "policy-author.yaml").exists():
        raise ValueError(
            f"{destination} is already a policy workspace; edit or remove it "
            "before initializing again"
        )
    discovery = discover_project(
        resolved_source,
        allowed_roots=(allowed_root,),
    )
    if not discovery.project.tools and not allow_no_actions:
        raise ValueError(
            "no supported agent actions were discovered; verify the source "
            "path and supported input formats, or rerun with --allow-no-actions "
            "when an empty workspace is intentional"
        )
    destination.mkdir(parents=True, exist_ok=True)
    config = PolicyWorkspaceConfig(
        project=discovery.project.name,
        source_root="",
        source_mode="workspace_relative",
        targets=(["opa", "agent-hooks", "acs"] if targets is None else targets),
    )
    try:
        config = config.model_copy(
            update={
                "source_root": os.path.relpath(
                    resolved_source,
                    destination,
                )
            }
        )
    except ValueError:
        config = config.model_copy(
            update={
                "source_root": str(resolved_source),
                "source_mode": "external_absolute",
            }
        )
    default_registry().validate_selection(config.targets)
    proposals = {proposal.target_tool: proposal for proposal in discovery.proposals}
    reviews = [
        _review_for_tool(
            tool,
            [item.rule.id for item in proposals[tool.name].recommendations]
            if tool.name in proposals
            else [],
            {
                item.kind
                for item in discovery.project.controls
                if item.target_tool == tool.name
            },
        )
        for tool in discovery.project.tools
    ]
    review = PolicyWorkspaceReview(
        project=discovery.project.name,
        actions=reviews,
        warnings=discovery.warnings,
    )
    _write_yaml(destination / "policy-author.yaml", config)
    _write_yaml(destination / "project.yaml", discovery.project)
    _write_yaml(
        destination / "actions.yaml",
        {"actions": reviews},
    )
    _write_yaml(destination / "context.yaml", discovery.project.context)
    _write_yaml(destination / "review.yaml", review)
    policy_directory = destination / config.policy_directory
    test_directory = destination / config.test_directory
    for proposal in discovery.proposals:
        policy = proposal.policy
        _write_yaml(
            policy_directory / f"{proposal.target_tool}.yaml",
            policy,
        )
        cases = generate_tests(
            policy,
            build_synthetic_context(
                discovery.project,
                proposal.target_tool,
            ),
        )
        _write_yaml(
            test_directory / f"{proposal.target_tool}.yaml",
            {
                "tool": proposal.target_tool,
                "cases": cases,
            },
        )
    readme = "\n".join(
        [
            "# Agent policy workspace",
            "",
            "This directory is the editable source of truth for agent policy.",
            "",
            (f"Resolved source: `{_resolve_workspace_source(config, destination)}`"),
            "",
            "1. Review `review.yaml` and each file in `policies/`.",
            "2. Edit policy rules and expected outcomes in `tests/`.",
            "3. From this directory, run `policy-author test-workspace .`.",
            (
                "4. Approve reviewed policies with `policy-author approve . "
                "--reviewer <identity> --rationale <reason>`."
            ),
            ("5. Generate target artifacts with `policy-author compile-workspace .`."),
            "",
            "Every policy includes `source_targets` pointing to the source file, "
            "line, and handler it governs.",
            "",
        ]
    )
    (destination / "README.md").write_text(readme, encoding="utf-8")
    return review


def refresh_workspace(path: Path) -> dict[str, Any]:
    root = _workspace_root(path)
    config = _load_config(root)
    discovery, reconciliation = _discover_workspace_source(root, config)
    if not reconciliation["required"]:
        _write_reconciliation_report(root, reconciliation)
        return {
            **reconciliation,
            "applied": False,
            "suggestions": [],
            "retired": [],
        }

    existing_review = load_workspace_review(root)
    existing_actions = {item.tool: item for item in existing_review.actions}
    proposals = {item.target_tool: item for item in discovery.proposals}
    observed_controls = {
        tool.name: {
            item.kind
            for item in discovery.project.controls
            if item.target_tool == tool.name
        }
        for tool in discovery.project.tools
    }
    reviews = [
        _review_for_tool(
            tool,
            [item.rule.id for item in proposals[tool.name].recommendations]
            if tool.name in proposals
            else [],
            observed_controls[tool.name],
        ).model_copy(
            update={
                "notes": (
                    existing_actions[tool.name].notes
                    if tool.name in existing_actions
                    else ""
                ),
            }
        )
        for tool in discovery.project.tools
    ]
    refreshed_review = PolicyWorkspaceReview(
        project=discovery.project.name,
        actions=reviews,
        warnings=discovery.warnings,
    )
    existing_context = _load_effective_project(root).context
    context_by_path = {item.path: item for item in existing_context.attributes}
    for attribute in discovery.project.context.attributes:
        context_by_path.setdefault(attribute.path, attribute)
    merged_context = ContextContract(
        attributes=sorted(context_by_path.values(), key=lambda item: item.path)
    )
    _write_yaml(root / "project.yaml", discovery.project)
    _write_yaml(root / "actions.yaml", {"actions": reviews})
    _write_yaml(root / "context.yaml", merged_context)
    _write_yaml(root / "review.yaml", refreshed_review)

    current_tools = {item.tool for item in existing_review.actions}
    discovered_tools = {item.name for item in discovery.project.tools}
    retired: list[str] = []
    retired_root = root / ".artifacts" / "retired"
    for tool in sorted(current_tools - discovered_tools):
        for directory in (config.policy_directory, config.test_directory):
            source_path = root / directory / f"{tool}.yaml"
            if not source_path.is_file():
                continue
            destination = retired_root / directory / source_path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_path.replace(destination)
            retired.append(str(destination.relative_to(root)))

    synthetic_by_tool = {
        tool.name: build_synthetic_context(discovery.project, tool.name)
        for tool in discovery.project.tools
    }
    suggestions: list[str] = []
    obligations: list[dict[str, Any]] = []
    suggestion_root = root / ".artifacts" / "reconciliation-suggestions"
    for tool in discovery.project.tools:
        policy_path = root / config.policy_directory / f"{tool.name}.yaml"
        test_path = root / config.test_directory / f"{tool.name}.yaml"
        proposal = proposals.get(tool.name)
        if policy_path.is_file():
            policy = load_policy(policy_path)
            policy = policy.model_copy(
                update={
                    "metadata": policy.metadata.model_copy(
                        update={"review_status": "needs_review"}
                    ),
                    "tool_schema_version": tool.schema_version,
                    "source_targets": _source_targets(tool),
                }
            )
            _write_yaml(policy_path, policy)
            if proposal is not None:
                suggestion_path = suggestion_root / f"{tool.name}.yaml"
                _write_yaml(suggestion_path, proposal.policy)
                suggestions.append(str(suggestion_path.relative_to(root)))
                current_rule_ids = {rule.id for rule in policy.rules}
                required_rule_ids = sorted(
                    {
                        rule.id
                        for rule in proposal.policy.rules
                        if rule.id not in current_rule_ids
                    }
                )
                if required_rule_ids:
                    obligation_id = (
                        f"reconciliation-{tool.name.replace('_', '-')}-"
                        f"{_json_digest(required_rule_ids)[:12]}"
                    )
                    obligations.append(
                        {
                            "id": obligation_id,
                            "tool": tool.name,
                            "suggestion": str(suggestion_path.relative_to(root)),
                            "required_rule_ids": required_rule_ids,
                            "resolution": (
                                "Merge the suggested rules or disposition this "
                                "finding during approval."
                            ),
                        }
                    )
        elif proposal is not None:
            _write_yaml(policy_path, proposal.policy)

        if not test_path.is_file() and proposal is not None:
            _write_yaml(
                test_path,
                {
                    "tool": tool.name,
                    "cases": generate_tests(
                        proposal.policy,
                        synthetic_by_tool[tool.name],
                    ),
                },
            )
        elif test_path.is_file():
            document = _read_mapping(test_path)
            required_arguments = (
                synthetic_by_tool[tool.name]
                .get("action", {})
                .get("arguments", {})
            )
            changed = False
            for case in document.get("cases", []):
                if not isinstance(case, dict):
                    continue
                context = case.get("context")
                if not isinstance(context, dict):
                    continue
                action = context.setdefault("action", {})
                if not isinstance(action, dict):
                    continue
                arguments = action.setdefault("arguments", {})
                if not isinstance(arguments, dict):
                    continue
                for name, value in required_arguments.items():
                    if name not in arguments:
                        arguments[name] = value
                        changed = True
            if changed:
                _write_yaml(test_path, document)

    obligated_tools = {str(item["tool"]) for item in obligations}
    for change in reconciliation["changes"]:
        if (
            change.get("kind") != "tool_changed"
            or "input_schema" not in change.get("fields", [])
            or not isinstance(change.get("tool"), str)
            or change["tool"] in obligated_tools
        ):
            continue
        tool_name = str(change["tool"])
        obligation_id = (
            f"reconciliation-{tool_name.replace('_', '-')}-schema-"
            f"{_json_digest(change)[:12]}"
        )
        obligations.append(
            {
                "id": obligation_id,
                "tool": tool_name,
                "suggestion": next(
                    (
                        item
                        for item in suggestions
                        if Path(item).stem == tool_name
                    ),
                    None,
                ),
                "required_rule_ids": [],
                "requires_disposition": True,
                "resolution": (
                    "Review the changed tool schema and disposition this "
                    "finding during approval because no new generated rule "
                    "fully represents the contract change."
                ),
            }
        )

    applied_report = {
        **reconciliation,
        "applied": True,
        "applied_at": datetime.now(UTC).isoformat(),
        "suggestions": suggestions,
        "obligations": obligations,
        "retired": retired,
    }
    _write_json_atomic(root / "discovery-reconciliation.json", applied_report)
    return applied_report


def load_workspace_review(path: Path) -> PolicyWorkspaceReview:
    root = _workspace_root(path)
    review_path = root / "review.yaml"
    try:
        return PolicyWorkspaceReview.model_validate(_read_mapping(review_path))
    except ValidationError as exc:
        raise ValueError(
            f"{review_path}: {format_validation_error(exc)}"
        ) from exc


def build_workbench_report(
    path: Path,
    *,
    run_tests: bool = True,
) -> dict[str, Any]:
    root = _workspace_root(path)
    config = _load_config(root)
    review = load_workspace_review(root)
    actionable = [
        _effective_action_review(root, config, item)
        for item in review.actions
        if item.review_status != "not_applicable"
    ]
    _, reconciliation = _discover_workspace_source(root, config)
    _write_reconciliation_report(root, reconciliation)
    if reconciliation["required"]:
        stale_policies: list[dict[str, Any]] = [
            {
                "tool": action.tool,
                "status": "needs_reconciliation",
                "risk": action.risk,
                "requires_approval": action.requires_approval,
                "rule_count": (
                    len(
                        load_policy(
                            root
                            / config.policy_directory
                            / f"{action.tool}.yaml"
                        ).rules
                    )
                    if (
                        root
                        / config.policy_directory
                        / f"{action.tool}.yaml"
                    ).is_file()
                    else 0
                ),
                "source": (
                    action.source_targets[0].model_dump(mode="json")
                    if action.source_targets
                    else None
                ),
                "questions": action.questions,
                "blocking_findings": action.blocking_findings,
                "unresolved_findings": action.blocking_findings,
                "tests": {
                    "status": "stale",
                    "passed": 0,
                    "total": 0,
                },
                "approval_current": False,
                "next_action": (
                    "Refresh the normalized inventory, review the discovery "
                    "changes, then update policy and tests."
                ),
            }
            for action in actionable
        ]
        workspace_argument = f'"{root}"'
        return {
            "project": review.project,
            "workspace": str(root),
            "resolved_source": str(_resolve_workspace_source(config, root)),
            "readiness": "needs_reconciliation",
            "tests": {
                "status": "stale",
                "error": (
                    "Normalized discovery differs from the reviewed workspace."
                ),
            },
            "summary": {
                "actions": len(review.actions),
                "policies": len(stale_policies),
                "approved": 0,
                "needs_review": len(stale_policies),
                "blocking_findings": sum(
                    len(item["blocking_findings"]) for item in stale_policies
                ),
            },
            "policies": stale_policies,
            "warnings": review.warnings,
            "reconciliation": reconciliation,
            "next_commands": [
                f"policy-author refresh-workspace {workspace_argument}",
                f"policy-author review {workspace_argument}",
                f"policy-author workbench {workspace_argument}",
            ],
        }
    test_report: dict[str, Any] | None = None
    test_error: str | None = None
    if run_tests and actionable:
        try:
            test_report = test_workspace(root)
        except (ValueError, RuntimeError) as exc:
            test_error = str(exc)

    test_results = {
        item["tool"]: item
        for item in (test_report or {}).get("results", [])
        if isinstance(item, dict) and isinstance(item.get("tool"), str)
    }
    policies: list[dict[str, Any]] = []
    for action in actionable:
        policy_path = root / config.policy_directory / f"{action.tool}.yaml"
        if not policy_path.is_file():
            policies.append(
                {
                    "tool": action.tool,
                    "status": "needs_review",
                    "risk": action.risk,
                    "requires_approval": action.requires_approval,
                    "rule_count": 0,
                    "source": (
                        action.source_targets[0].model_dump(mode="json")
                        if action.source_targets
                        else None
                    ),
                    "questions": action.questions,
                    "blocking_findings": action.blocking_findings,
                    "unresolved_findings": action.blocking_findings,
                    "tests": {"status": "blocked", "passed": 0, "total": 0},
                    "approval_current": False,
                    "approval_eligible": False,
                    "approval_block_reason": (
                        "Author at least one explicit decision rule before approval."
                    ),
                    "next_action": (
                        "Classify the action risk and refresh the workspace "
                        "before authoring or approving policy."
                    ),
                }
            )
            continue
        policy = load_policy(policy_path)
        result = test_results.get(action.tool)
        tests_passed = bool(result and result.get("passed"))
        approval = action.approval
        snapshot = (
            _approval_snapshot(
                root,
                config,
                action,
                result,
                approval.finding_dispositions if approval is not None else [],
                source_revision=str(test_report.get("source_revision")),
                targets=config.targets,
            )
            if test_report is not None and result is not None
            else None
        )
        approval_current = bool(
            approval is not None
            and snapshot is not None
            and not _approval_stale_fields(approval, snapshot)
            and policy.metadata.review_status == "approved"
            and _approval_dispositions_current(approval)
        )
        unresolved_findings = (
            [] if approval_current else list(action.blocking_findings)
        )
        approval_block_reason: str | None = None
        if not tests_passed:
            approval_block_reason = (
                "Run nonempty passing policy tests before approval."
            )
        elif "incomplete_policy_synthesis" in unresolved_findings:
            approval_block_reason = (
                "Author at least one explicit decision rule before approval."
            )
        if test_error is not None or (result is not None and not tests_passed):
            status = "failed"
            next_action = (
                "Edit the policy or tests, then rerun policy-author workbench."
            )
        elif not run_tests:
            status = "not_run"
            next_action = "Rerun policy-author workbench with --test enabled."
        elif approval_current:
            status = "approved"
            next_action = "Ready for policy-author compile-workspace."
        elif action.review_status == "rejected":
            status = "rejected"
            next_action = "Revise the rejected policy before requesting review."
        elif action.review_status == "approved":
            status = "needs_review"
            next_action = (
                "Approval evidence is stale; review and approve the policy again."
            )
        else:
            status = "needs_review"
            next_action = "Review policy and tests, then run policy-author approve."
        source = action.source_targets[0] if action.source_targets else None
        policies.append(
            {
                "tool": action.tool,
                "status": status,
                "risk": action.risk,
                "requires_approval": action.requires_approval,
                "rule_count": len(policy.rules),
                "source": (
                    source.model_dump(mode="json") if source is not None else None
                ),
                "questions": action.questions,
                "blocking_findings": action.blocking_findings,
                "unresolved_findings": unresolved_findings,
                "tests": {
                    "status": (
                        "passed"
                        if tests_passed
                        else "failed"
                        if result is not None or test_error is not None
                        else "not_run"
                    ),
                    "passed": (
                        sum(bool(case.get("passed")) for case in result["cases"])
                        if result is not None
                        else 0
                    ),
                    "total": (len(result["cases"]) if result is not None else 0),
                },
                "approval_current": approval_current,
                "approval_eligible": approval_block_reason is None,
                "approval_block_reason": approval_block_reason,
                "next_action": next_action,
            }
        )

    if not policies:
        readiness = "not_applicable"
    elif test_error is not None or any(
        item["tests"]["status"] == "failed" for item in policies
    ):
        readiness = "failed"
    elif not run_tests:
        readiness = "not_run"
    elif all(item["approval_current"] for item in policies):
        readiness = "passed"
    else:
        readiness = "needs_review"

    workspace_argument = f'"{root}"'
    next_commands = []
    if readiness == "failed":
        next_commands.append(f"policy-author workbench {workspace_argument}")
    elif readiness == "not_run":
        next_commands.append(f"policy-author workbench {workspace_argument} --test")
    elif readiness == "needs_review":
        next_commands.extend(
            [
                f"policy-author review {workspace_argument}",
                f"policy-author approval-preview {workspace_argument}",
                f"policy-author approve {workspace_argument} --tool <name|all> "
                "--reviewer <identity> --rationale <reason> "
                "--confirm-snapshot <digest>",
            ]
        )
    elif readiness == "passed":
        next_commands.append(f"policy-author compile-workspace {workspace_argument}")

    return {
        "project": review.project,
        "workspace": str(root),
        "resolved_source": str(_resolve_workspace_source(config, root)),
        "readiness": readiness,
        "tests": {
            "status": (
                "not_applicable"
                if not policies
                else "failed"
                if test_error is not None
                else "not_run"
                if not run_tests
                else "passed"
                if test_report is not None and test_report.get("passed")
                else "failed"
            ),
            "error": test_error,
        },
        "summary": {
            "actions": len(review.actions),
            "policies": len(policies),
            "approved": sum(bool(item["approval_current"]) for item in policies),
            "needs_review": sum(
                not bool(item["approval_current"]) for item in policies
            ),
            "blocking_findings": sum(
                len(item["unresolved_findings"]) for item in policies
            ),
        },
        "policies": policies,
        "warnings": review.warnings,
        "reconciliation": reconciliation,
        "next_commands": next_commands,
    }


def _load_config(root: Path) -> PolicyWorkspaceConfig:
    config_path = root / "policy-author.yaml"
    mapping = _read_mapping(config_path)
    if "source_mode" not in mapping:
        raise ValueError(
            "workspace uses an unsafe legacy absolute source binding; "
            "reinitialize it with this version"
        )
    try:
        return PolicyWorkspaceConfig.model_validate(mapping)
    except ValidationError as exc:
        raise ValueError(
            f"{config_path}: {format_validation_error(exc)}"
        ) from exc


def _policy_paths(
    root: Path,
    config: PolicyWorkspaceConfig,
) -> list[Path]:
    directory = root / config.policy_directory
    return sorted(directory.glob("*.yaml")) if directory.exists() else []


def build_approval_packet(
    path: Path,
    *,
    tool_name: str | None = None,
    finding_dispositions: list[FindingDisposition] | None = None,
    semantic_acknowledgements: list[str] | None = None,
) -> dict[str, Any]:
    root = _workspace_root(path)
    config = _load_config(root)
    _ensure_discovery_reconciled(root, config)
    project = _load_effective_project(root)
    review = load_workspace_review(root)
    _ensure_no_unclassified_actions(review)
    effective_actions = [
        _effective_action_review(root, config, item) for item in review.actions
    ]
    selected = {
        item.tool
        for item in effective_actions
        if tool_name in {None, "all", item.tool}
        and item.review_status != "not_applicable"
    }
    if not selected:
        raise ValueError("no reviewable policies matched the approval selection")
    dispositions = finding_dispositions or []
    disposition_by_id = {
        item.finding_id: _canonical_disposition_payload(item)
        for item in dispositions
    }
    test_report_path = root / "test-results.json"
    test_report = (
        json.loads(test_report_path.read_text(encoding="utf-8"))
        if test_report_path.is_file()
        else {}
    )
    test_results = {
        item["tool"]: item
        for item in test_report.get("results", [])
        if isinstance(item, dict) and isinstance(item.get("tool"), str)
    }
    registry = default_registry()
    policies = []
    required_acknowledgements: set[str] = set()
    for action in effective_actions:
        if action.tool not in selected:
            continue
        policy_path = root / config.policy_directory / f"{action.tool}.yaml"
        test_path = root / config.test_directory / f"{action.tool}.yaml"
        policy = load_policy(policy_path)
        if (
            "incomplete_policy_synthesis" in action.blocking_findings
            and not policy.rules
        ):
            raise ValueError(
                f"{action.tool}: policy has no rules and cannot be approved; "
                "author at least one explicit decision rule first"
            )
        target_fidelity = {}
        for target in config.targets:
            compilation = registry.get(target).compile(policy, project)
            target_fidelity[target] = {
                "adapter_identity": registry.get(target).identity,
                "compatible": compilation.compatible,
                "compatibility": [
                    item.model_dump(mode="json") for item in compilation.compatibility
                ],
            }
            required_acknowledgements.update(
                f"{target}:{item.rule_id}"
                for item in compilation.compatibility
                if item.fidelity == "lossy_fail_closed"
            )
        policies.append(
            {
                "tool": action.tool,
                "source_targets": [
                    item.model_dump(mode="json") for item in action.source_targets
                ],
                "policy_path": str(policy_path.relative_to(root)),
                "test_path": str(test_path.relative_to(root)),
                "default_decision": policy.default_decision,
                "rules": [
                    {
                        "id": rule.id,
                        "decision": rule.decision,
                        "reason": rule.reason,
                        "condition": rule.condition.model_dump(mode="json"),
                    }
                    for rule in policy.rules
                ],
                "tests": _read_mapping(test_path).get("cases", []),
                "test_result": test_results.get(action.tool),
                "blocking_findings": action.blocking_findings,
                "proposed_dispositions": [
                    disposition_by_id[finding]
                    for finding in action.blocking_findings
                    if finding in disposition_by_id
                ],
                "target_fidelity": target_fidelity,
            }
        )
    packet = {
        "schema_version": "policyauthor.dev/approval-packet/v1alpha1",
        "project": project.name,
        "workspace": str(root),
        "resolved_source": str(_resolve_workspace_source(config, root)),
        "source_revision": _source_revision(config, root),
        "product_version": __version__,
        "targets": config.targets,
        "adapter_identities": _adapter_identities(config.targets),
        "context": project.context.model_dump(mode="json"),
        "workspace_digests": {
            "project": _file_digest(root / "project.yaml"),
            "context": _file_digest(root / "context.yaml"),
            "configuration": _file_digest(root / "policy-author.yaml"),
        },
        "policies": policies,
        "required_semantic_acknowledgements": sorted(required_acknowledgements),
        "proposed_semantic_acknowledgements": sorted(semantic_acknowledgements or []),
    }
    packet["confirmation_digest"] = _json_digest(packet)
    _write_json_atomic(root / "approval-packet.json", packet)
    return packet


def approve_workspace(
    path: Path,
    *,
    tool_name: str | None = None,
    reviewer: str,
    rationale: str,
    reviewer_role: str | None = None,
    finding_dispositions: list[FindingDisposition] | None = None,
    approval_packet_digest: str | None = None,
    semantic_acknowledgements: list[str] | None = None,
) -> int:
    root = _workspace_root(path)
    config = _load_config(root)
    review = load_workspace_review(root)
    _ensure_discovery_reconciled(root, config)
    _ensure_no_unclassified_actions(review)
    effective_actions = [
        _effective_action_review(root, config, item) for item in review.actions
    ]
    if tool_name is None or tool_name == "all":
        selected: set[str] = {item.tool for item in review.actions}
    else:
        selected = {tool_name}
    known = {item.tool for item in effective_actions}
    unknown = selected - known
    if unknown:
        raise ValueError(f"unknown workspace tool(s): {', '.join(sorted(unknown))}")
    test_report_path = root / "test-results.json"
    if not test_report_path.is_file():
        raise ValueError("run test-workspace before approving policies")
    try:
        test_report = json.loads(test_report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{test_report_path}: invalid test report: {exc}") from exc
    test_results = {
        item["tool"]: item
        for item in test_report.get("results", [])
        if isinstance(item, dict) and isinstance(item.get("tool"), str)
    }
    current_revision = _source_revision(config, root)
    if test_report.get("source_revision") != current_revision:
        raise ValueError("test evidence is stale because the source revision changed")
    current_evidence = {
        "project_digest": _file_digest(root / "project.yaml"),
        "context_digest": _file_digest(root / "context.yaml"),
        "workspace_config_digest": _file_digest(root / "policy-author.yaml"),
        "product_version": __version__,
    }
    for key, value in current_evidence.items():
        if test_report.get(key) != value:
            label = key.removesuffix("_digest").replace("_", " ")
            raise ValueError(f"test evidence is stale because {label} changed")
    approvals: dict[str, ApprovalEvidence] = {}
    supplied_dispositions = finding_dispositions or []
    packet = build_approval_packet(
        root,
        tool_name=tool_name,
        finding_dispositions=supplied_dispositions,
        semantic_acknowledgements=semantic_acknowledgements,
    )
    packet_digest = str(packet["confirmation_digest"])
    if approval_packet_digest is None:
        raise ValueError(
            "approval requires the confirmation digest from approval-preview"
        )
    if approval_packet_digest != packet_digest:
        raise ValueError(
            "approval packet changed; review the current packet and confirm "
            f"{packet_digest}"
        )
    required_acknowledgements = set(packet["required_semantic_acknowledgements"])
    supplied_acknowledgements = set(semantic_acknowledgements or [])
    missing_acknowledgements = sorted(
        required_acknowledgements - supplied_acknowledgements
    )
    unknown_acknowledgements = sorted(
        supplied_acknowledgements - required_acknowledgements
    )
    if missing_acknowledgements:
        raise ValueError(
            "lossy target semantics require acknowledgement for "
            + ", ".join(missing_acknowledgements)
        )
    if unknown_acknowledgements:
        raise ValueError(
            "unknown semantic acknowledgements: " + ", ".join(unknown_acknowledgements)
        )
    disposition_ids = [item.finding_id for item in supplied_dispositions]
    if len(disposition_ids) != len(set(disposition_ids)):
        raise ValueError("finding dispositions must not contain duplicate IDs")
    disposition_by_id = {item.finding_id: item for item in supplied_dispositions}
    selected_findings = {
        finding
        for action in effective_actions
        if action.tool in selected
        for finding in action.blocking_findings
    }
    unknown_findings = sorted(set(disposition_by_id) - selected_findings)
    if unknown_findings:
        raise ValueError(
            "finding dispositions reference unknown findings: "
            + ", ".join(unknown_findings)
        )
    for action in effective_actions:
        if action.tool not in selected or action.review_status == "not_applicable":
            continue
        policy_path = root / config.policy_directory / f"{action.tool}.yaml"
        test_path = root / config.test_directory / f"{action.tool}.yaml"
        result = test_results.get(action.tool)
        if result is None:
            raise ValueError(f"{action.tool}: no current test result was found")
        if not result.get("passed") or int(result.get("case_count", 0)) < 1:
            raise ValueError(f"{action.tool}: tests must be nonempty and passing")
        policy_digest = _policy_digest(policy_path)
        test_digest = _file_digest(test_path)
        if result.get("policy_digest") != policy_digest:
            raise ValueError(f"{action.tool}: policy changed after tests ran")
        if result.get("test_digest") != test_digest:
            raise ValueError(f"{action.tool}: tests changed after tests ran")
        dispositions = [
            disposition_by_id[item]
            for item in action.blocking_findings
            if item in disposition_by_id
        ]
        if "incomplete_policy_synthesis" in action.blocking_findings:
            policy = load_policy(policy_path)
            if not policy.rules:
                raise ValueError(
                    f"{action.tool}: policy has no rules and cannot be approved"
                )
        missing_findings = sorted(
            set(action.blocking_findings) - set(disposition_by_id)
        )
        if missing_findings:
            raise ValueError(
                f"{action.tool}: unresolved findings require structured "
                "dispositions for " + ", ".join(missing_findings)
            )
        if any(item.disposition == "resolved" for item in dispositions):
            raise ValueError(
                f"{action.tool}: active findings cannot be marked resolved; "
                "rerun discovery after remediation so the finding disappears"
            )
        false_positives = [
            item for item in dispositions if item.disposition == "false_positive"
        ]
        if false_positives and not reviewer_role:
            raise ValueError(
                f"{action.tool}: false-positive dispositions require --reviewer-role"
            )
        if any(not item.evidence for item in false_positives):
            raise ValueError(
                f"{action.tool}: false-positive dispositions require evidence"
            )
        if (
            any(item.disposition == "accepted_risk" for item in dispositions)
            and not reviewer_role
        ):
            raise ValueError(f"{action.tool}: accepted risk requires --reviewer-role")
        accepted_risks = [
            item for item in dispositions if item.disposition == "accepted_risk"
        ]
        now = datetime.now(UTC)
        for item in accepted_risks:
            if item.expires_at is None:
                raise ValueError(f"{action.tool}: accepted risk requires an expiry")
            expiry = item.expires_at
            if expiry.tzinfo is None or expiry <= now:
                raise ValueError(
                    f"{action.tool}: accepted-risk expiry must be a future "
                    "timezone-aware timestamp"
                )
            if not item.evidence:
                raise ValueError(f"{action.tool}: accepted risk requires evidence")
            if not item.compensating_controls:
                raise ValueError(
                    f"{action.tool}: accepted risk requires compensating controls"
                )
        dispositions = [
            item.model_copy(update={"owner": item.owner or reviewer})
            for item in dispositions
        ]
        snapshot = _approval_snapshot(
            root,
            config,
            action,
            result,
            dispositions,
            source_revision=current_revision,
            targets=config.targets,
        )
        evidence = ApprovalEvidence(
            reviewer=reviewer,
            reviewer_role=reviewer_role,
            approved_at=datetime.now(UTC).isoformat(),
            rationale=rationale,
            source_revision=current_revision,
            policy_digest=str(snapshot["policy_digest"]),
            test_digest=str(snapshot["test_digest"]),
            test_result_digest=str(snapshot["test_result_digest"]),
            project_digest=str(snapshot["project_digest"]),
            context_digest=str(snapshot["context_digest"]),
            workspace_config_digest=str(snapshot["workspace_config_digest"]),
            findings_digest=str(snapshot["findings_digest"]),
            adapter_identities=dict(snapshot["adapter_identities"]),
            snapshot_digest=str(snapshot["snapshot_digest"]),
            product_version=__version__,
            approval_packet_digest=packet_digest,
            semantic_acknowledgements=sorted(supplied_acknowledgements),
            finding_dispositions=dispositions,
            targets=config.targets,
        )
        stale = _approval_stale_fields(evidence, snapshot)
        if stale:
            raise RuntimeError(
                f"{action.tool}: constructed approval is stale because "
                + ", ".join(stale)
                + " changed"
            )
        approvals[action.tool] = evidence

    approved = 0
    updated_actions = []
    for action in review.actions:
        approval_record = approvals.get(action.tool)
        if approval_record is None:
            updated_actions.append(action)
            continue
        updated_actions.append(
            action.model_copy(
                update={
                    "review_status": "approved",
                    "approval": approval_record,
                }
            )
        )
        policy_path = root / config.policy_directory / f"{action.tool}.yaml"
        policy = load_policy(policy_path)
        policy = policy.model_copy(
            update={
                "metadata": policy.metadata.model_copy(
                    update={"review_status": "approved"}
                )
            }
        )
        _write_yaml(policy_path, policy)
        approved += 1
    updated_review = review.model_copy(update={"actions": updated_actions})
    _write_yaml(root / "review.yaml", updated_review)
    _write_yaml(root / "actions.yaml", {"actions": updated_actions})
    return approved


def _load_test_cases(path: Path) -> list[PolicyTestCase]:
    document = _read_mapping(path)
    cases = document.get("cases", [])
    if not isinstance(cases, list):
        raise ValueError(f"{path}: cases must be a list")
    if not cases:
        raise ValueError(f"{path}: at least one test case is required")
    try:
        validated = [PolicyTestCase.model_validate(item) for item in cases]
        require_unique_test_ids(validated)
        return validated
    except ValidationError as exc:
        raise ValueError(
            f"{path}: {format_validation_error(exc)}"
        ) from exc


def test_workspace(path: Path) -> dict[str, Any]:
    root = _workspace_root(path)
    config = _load_config(root)
    _ensure_discovery_reconciled(root, config)
    _ensure_no_unclassified_actions(load_workspace_review(root))
    project = _load_effective_project(root)
    source_revision = _source_revision(config, root)
    results = []
    for policy_path in _policy_paths(root, config):
        policy = load_policy(policy_path)
        require_valid_policy(policy, project)
        test_path = root / config.test_directory / policy_path.name
        cases = _load_test_cases(test_path)
        case_results = []
        for case in cases:
            decision = evaluate_policy(policy, case.context)
            case_results.append(
                {
                    "id": case.id,
                    "expected": case.expected_decision,
                    "actual": decision.decision,
                    "passed": decision.decision == case.expected_decision,
                    "matched_rule_ids": decision.matched_rule_ids,
                    "reason": decision.reason,
                }
            )
        results.append(
            {
                "tool": policy.tool,
                "passed": bool(case_results)
                and all(item["passed"] for item in case_results),
                "case_count": len(case_results),
                "policy_digest": _policy_digest(policy_path),
                "test_digest": _file_digest(test_path),
                "cases": case_results,
                "source_targets": [
                    item.model_dump(mode="json") for item in policy.source_targets
                ],
            }
        )
    report = {
        "project": project.name,
        "resolved_source": str(_resolve_workspace_source(config, root)),
        "generated_at": datetime.now(UTC).isoformat(),
        "source_revision": source_revision,
        "project_digest": _file_digest(root / "project.yaml"),
        "context_digest": _file_digest(root / "context.yaml"),
        "workspace_config_digest": _file_digest(root / "policy-author.yaml"),
        "product_version": __version__,
        "policies": len(results),
        "passed": bool(results) and all(item["passed"] for item in results),
        "results": results,
    }
    (root / "test-results.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    return report


def _artifact_entries(root: Path) -> list[dict[str, str]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256_bytes(path.read_bytes()),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "publication-manifest.json"
    ]


def _integration_contract(
    target: str,
    policy: CanonicalPolicy,
    project: ProjectDefinition,
) -> dict[str, Any]:
    tool = next(item for item in project.tools if item.name == policy.tool)
    package = policy.metadata.name.replace("-", "_")
    entrypoints: dict[str, dict[str, Any]] = {
        "opa": {
            "artifact": f"policy/{package}.rego",
            "query": f"data.policy_authoring.{package}.decision",
        },
        "acs": {
            "artifact": f"acs/policy/{package}.rego",
            "query": f"data.policy_authoring.{package}.decision",
        },
        "cedar": {
            "artifact": f"policy/{policy.metadata.name}.cedar",
            "schema": "policy/schema.json",
            "action": policy.tool,
        },
        "cerbos": {
            "artifact": f"policies/{policy.metadata.name}.yaml",
            "resource_kind": f"agent_tool_{policy.tool}",
            "action": policy.tool,
        },
        "agent-hooks": {
            "artifact": "agent-hooks/binding.json",
            "evaluator_target": "opa",
        },
    }
    return {
        "schema_version": "policyauthor.dev/integration-contract/v1alpha1",
        "target": target,
        "tool": policy.tool,
        "interception_point": policy.interception_point,
        "entrypoint": entrypoints[target],
        "input": {
            "tool_arguments_schema": tool.input_schema,
            "trusted_context": [
                item.model_dump(mode="json")
                for item in project.context.attributes
                if item.trust not in {"model_provided", "untrusted"}
            ],
        },
        "output": {
            "decision": [
                "allow",
                "deny",
                "warn",
                "escalate",
                "transform",
            ],
            "matched_rule_ids": "array[string]",
            "reason": "string",
        },
        "host_requirements": {
            "trusted_context_must_not_come_from_model": True,
            "verify_bundle_before_loading": True,
            "resolve_bundle_from_current_json": True,
            "failure_mode": "deny",
        },
    }


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


def _replace_directories_atomically(
    replacements: list[tuple[Path, Path]],
    commit: Callable[[], None],
) -> None:
    prepared: list[tuple[Path, Path, Path, bool]] = []
    try:
        for source, destination in replacements:
            replacement = destination.with_name(destination.name + ".next")
            backup = destination.with_name(destination.name + ".previous")
            for path in (replacement, backup):
                if path.exists():
                    shutil.rmtree(path)
            prepared.append((destination, replacement, backup, destination.exists()))
            shutil.copytree(source, replacement)
    except BaseException:
        for _, replacement, backup, _ in prepared:
            if replacement.exists():
                shutil.rmtree(replacement)
            if backup.exists():
                shutil.rmtree(backup)
        raise

    swapped: list[tuple[Path, Path, Path, bool]] = []
    try:
        for destination, replacement, backup, existed in prepared:
            if existed:
                destination.rename(backup)
            swapped.append((destination, replacement, backup, existed))
            replacement.rename(destination)
        commit()
    except BaseException:
        for destination, _, backup, existed in reversed(swapped):
            if destination.exists():
                shutil.rmtree(destination)
            if existed and backup.exists():
                backup.rename(destination)
        raise
    finally:
        for _, replacement, backup, _ in prepared:
            if replacement.exists():
                shutil.rmtree(replacement)
            if backup.exists():
                shutil.rmtree(backup)


def _product_commit() -> str:
    try:
        build_info = importlib.import_module("policy_authoring._build_info")
    except ModuleNotFoundError:
        build_commit = "unknown"
    else:
        build_commit = str(getattr(build_info, "SOURCE_COMMIT", "unknown"))
    if build_commit != "unknown":
        return build_commit
    repository = Path(__file__).resolve().parents[4]
    completed = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _product_dirty() -> bool | None:
    try:
        build_info = importlib.import_module("policy_authoring._build_info")
    except ModuleNotFoundError:
        repository = Path(__file__).resolve().parents[4]
        completed = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return bool(completed.stdout.strip()) if completed.returncode == 0 else None
    return str(getattr(build_info, "SOURCE_DIRTY", "false")).lower() == "true"


def product_provenance() -> dict[str, Any]:
    try:
        importlib.import_module("policy_authoring._build_info")
        packaged = True
    except ModuleNotFoundError:
        packaged = False
    return {
        "name": "agent-policy-author",
        "version": __version__,
        "commit": _product_commit(),
        "dirty": _product_dirty(),
        "packaged": packaged,
    }


def verify_publication_bundle(
    path: Path,
    *,
    require_validated: bool = False,
) -> dict[str, Any]:
    root = path.resolve(strict=True)
    manifest_path = root / "publication-manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"{root}: publication-manifest.json is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{manifest_path}: invalid manifest: {exc}") from exc
    if manifest.get("authority") != "authoritative":
        raise ValueError("bundle is not authoritative")
    expected_entries = manifest.get("artifacts")
    if not isinstance(expected_entries, list):
        raise ValueError("manifest artifacts must be a list")
    expected: dict[str, str] = {}
    for item in expected_entries:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
        ):
            raise ValueError("manifest contains an invalid artifact entry")
        artifact_path = str(item["path"])
        if artifact_path in expected:
            raise ValueError(f"manifest contains duplicate artifact {artifact_path}")
        expected[artifact_path] = str(item["sha256"])
    actual = {item["path"]: item["sha256"] for item in _artifact_entries(root)}
    if actual != expected:
        raise ValueError("bundle artifact hashes do not match the manifest")
    payload = dict(manifest)
    manifest_digest = payload.pop("manifest_digest", None)
    if manifest_digest != _json_digest(payload):
        raise ValueError("bundle manifest digest is invalid")
    bundle_payload = dict(payload)
    bundle_digest = bundle_payload.pop("bundle_digest", None)
    bundle_payload.pop("compiled_at", None)
    if bundle_digest != _json_digest(_bundle_identity_payload(bundle_payload)):
        raise ValueError("bundle content digest is invalid")
    digest_name = str(bundle_digest).removeprefix("sha256:")
    if root.parent.name == "bundles" and root.name != digest_name:
        raise ValueError("bundle directory does not match its manifest digest")
    validation = manifest.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("bundle validation evidence is missing")
    fully_validated = validation.get("verified") is True
    native_validation_complete = (
        validation.get("native_validation_complete") is True
    )
    if require_validated and not fully_validated:
        raise ValueError(
            "bundle integrity is valid but target validation is incomplete"
        )
    return {
        "authority": "authoritative",
        "bundle_digest": bundle_digest,
        "artifacts": len(actual),
        "integrity_verified": True,
        "fully_validated": fully_validated,
        "native_validation_complete": native_validation_complete,
        "assurance_summary": validation.get("assurance_summary", {}),
        "publication_profile": manifest.get("publication_profile"),
        "validation": validation,
    }


def export_policy_package(
    path: Path,
    *,
    tool_name: str,
    target: str,
    destination: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    root = _workspace_root(path)
    generated = root / "generated"
    current_path = generated / "current.json"
    if not current_path.is_file():
        raise ValueError(
            "no authoritative bundle is available; compile the reviewed workspace first"
        )
    try:
        current = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"{current_path}: invalid current bundle pointer: {exc}"
        ) from exc
    bundle_reference = current.get("bundle")
    if not isinstance(bundle_reference, str) or not bundle_reference:
        raise ValueError("current bundle pointer does not identify a bundle")
    bundle = (generated / bundle_reference).resolve(strict=True)
    bundles_root = (generated / "bundles").resolve(strict=True)
    if not bundle.is_relative_to(bundles_root):
        raise ValueError(
            "current bundle pointer escapes the authoritative bundle store"
        )
    verification = verify_publication_bundle(bundle)
    package = bundle / tool_name / target
    if not package.is_dir():
        available_root = bundle / tool_name
        available = (
            sorted(item.name for item in available_root.iterdir() if item.is_dir())
            if available_root.is_dir()
            else []
        )
        detail = f"; available targets: {', '.join(available)}" if available else ""
        raise ValueError(
            f"the authoritative bundle has no {target!r} package for "
            f"{tool_name!r}{detail}"
        )
    archive = destination.expanduser().resolve()
    if archive.suffix.lower() != ".zip":
        archive = archive.with_suffix(".zip")
    if archive.is_relative_to(bundle):
        raise ValueError("export destination cannot be inside the authoritative bundle")
    if archive.exists() and not overwrite:
        raise ValueError(
            f"{archive} already exists; choose another path or allow replacement"
        )
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_name(f".{archive.name}.tmp")
    if temporary.exists():
        temporary.unlink()
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as exported:
            for artifact in sorted(package.rglob("*")):
                if artifact.is_file():
                    exported.write(
                        artifact,
                        artifact.relative_to(package).as_posix(),
                    )
        os.replace(temporary, archive)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "archive": str(archive),
        "tool": tool_name,
        "target": target,
        "bundle_digest": verification["bundle_digest"],
        "files": sum(1 for item in package.rglob("*") if item.is_file()),
    }


def compile_workspace(
    path: Path,
    *,
    targets: list[str] | None = None,
    require_validated: bool = False,
    require_exact_semantics: bool = False,
    allow_dirty_product: bool = False,
) -> dict[str, Any]:
    root = _workspace_root(path)
    config = _load_config(root)
    provenance = product_provenance()
    if (
        provenance["packaged"]
        and provenance["dirty"] is True
        and not allow_dirty_product
    ):
        raise ValueError(
            "installed product build has dirty source provenance; rebuild from "
            "a clean commit or explicitly acknowledge --allow-dirty-product"
        )
    _ensure_discovery_reconciled(root, config)
    project = _load_effective_project(root)
    review = load_workspace_review(root)
    reviews = {
        item.tool: _effective_action_review(root, config, item)
        for item in review.actions
    }
    source_revision = _source_revision(config, root)
    policy_paths = _policy_paths(root, config)
    for policy_path in policy_paths:
        policy = load_policy(policy_path)
        if policy.metadata.review_status != "approved":
            raise ValueError(
                f"{policy.tool} is {policy.metadata.review_status}; approve it"
            )
    test_report_path = root / "test-results.json"
    if not test_report_path.is_file():
        raise ValueError("run test-workspace before compiling policies")
    try:
        test_report = json.loads(test_report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{test_report_path}: invalid test report: {exc}") from exc
    test_results = {
        item["tool"]: item
        for item in test_report.get("results", [])
        if isinstance(item, dict) and isinstance(item.get("tool"), str)
    }
    if test_report.get("source_revision") != source_revision:
        raise ValueError("test evidence is stale because the source revision changed")
    selected_targets = config.targets if targets is None else targets
    if not selected_targets:
        raise ValueError("at least one compilation target is required")
    if len(selected_targets) != len(set(selected_targets)):
        raise ValueError("compilation targets must be unique")
    registry = default_registry()
    compilation_targets = registry.order_selection(selected_targets)
    unapproved_targets = sorted(set(selected_targets) - set(config.targets))
    if unapproved_targets:
        raise ValueError(
            "target override includes targets outside workspace approval scope: "
            + ", ".join(unapproved_targets)
        )
    generated = root / config.generated_directory
    results = []
    approvals: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="policy-author-workspace-") as temp:
        staging = Path(temp)
        for policy_path in policy_paths:
            policy = load_policy(policy_path)
            require_valid_policy(policy, project)
            action = reviews.get(policy.tool)
            if action is None:
                raise ValueError(f"{policy.tool}: review record is missing")
            approval = action.approval
            if approval is None:
                raise ValueError(f"{policy.tool}: approval evidence is missing")
            if not _approval_dispositions_current(approval):
                raise ValueError(
                    f"{policy.tool}: approval is stale because an accepted-risk "
                    "disposition expired"
                )
            if approval.source_revision != source_revision:
                raise ValueError(
                    f"{policy.tool}: approval is stale because source changed"
                )
            result = test_results.get(policy.tool)
            if result is None:
                raise ValueError(f"{policy.tool}: current test result is missing")
            if not result.get("passed") or int(result.get("case_count", 0)) < 1:
                raise ValueError(
                    f"{policy.tool}: current tests must be nonempty and passing"
                )
            snapshot = _approval_snapshot(
                root,
                config,
                action,
                result,
                approval.finding_dispositions,
                source_revision=source_revision,
                targets=config.targets,
            )
            stale = _approval_stale_fields(approval, snapshot)
            if stale:
                raise ValueError(
                    f"{policy.tool}: approval is stale because "
                    + ", ".join(stale)
                    + " changed"
                )
            if not set(selected_targets).issubset(approval.targets):
                raise ValueError(
                    f"{policy.tool}: selected targets are outside approval scope"
                )
            target_results: dict[str, dict[str, Any]] = {}
            for target in compilation_targets:
                compilation = registry.get(target).compile(policy, project)
                inexact = [
                    item
                    for item in compilation.compatibility
                    if item.fidelity != "exact"
                ]
                if require_exact_semantics and inexact:
                    affected_rules = ", ".join(
                        f"{item.rule_id} ({item.fidelity})"
                        for item in inexact
                    )
                    target_results[target] = {
                        "rendered": False,
                        "validation": "failed",
                        "detail": (
                            "exact semantics required, but target translation is "
                            f"inexact for: {affected_rules}"
                        ),
                    }
                    continue
                if not compilation.compatible:
                    target_results[target] = {
                        "rendered": False,
                        "validation": "failed",
                        "detail": ("canonical features are unsupported by this target"),
                    }
                    continue
                if not compilation.artifacts:
                    target_results[target] = {
                        "rendered": False,
                        "validation": "failed",
                        "detail": "compatible target produced no artifacts",
                    }
                    continue
                target_staging = staging / policy.tool / target
                for artifact in compilation.artifacts:
                    destination = target_staging / artifact.path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(artifact.content, encoding="utf-8")
                _write_json_atomic(
                    target_staging / "integration-contract.json",
                    _integration_contract(target, policy, project),
                )
                validation = validate_target(target, target_staging)
                target_results[target] = {
                    "rendered": True,
                    "validation": validation["status"],
                    "detail": validation["detail"],
                    "assurance": validation.get("assurance"),
                    "validator": validation.get("validator"),
                }
                (target_staging / "compilation.json").write_text(
                    compilation.model_dump_json(indent=2),
                    encoding="utf-8",
                )
            approvals.append(
                {
                    "tool": policy.tool,
                    "evidence": approval.model_dump(mode="json"),
                }
            )
            results.append(
                {
                    "tool": policy.tool,
                    "review_status": policy.metadata.review_status,
                    "targets": target_results,
                    "source_targets": [
                        item.model_dump(mode="json") for item in policy.source_targets
                    ],
                }
            )
        compatible = bool(results)
        verified = bool(results)
        assurance_values: list[str] = []
        target_result_count = 0
        for item in results:
            target_values = item["targets"]
            assert isinstance(target_values, dict)
            target_result_count += len(target_values)
            assurance_values.extend(
                str(value["assurance"])
                for value in target_values.values()
                if value.get("assurance") is not None
            )
            compatible = compatible and all(
                value["rendered"] and value["validation"] != "failed"
                for value in target_values.values()
            )
            verified = verified and all(
                value["validation"] == "validated" for value in target_values.values()
            )
        assurance_summary = {
            assurance: assurance_values.count(assurance)
            for assurance in sorted(set(assurance_values))
        }
        native_validation_complete = (
            verified
            and len(assurance_values) == target_result_count
            and all(assurance == "native" for assurance in assurance_values)
        )
        if require_validated and not verified:
            compatible = False
        report = {
            "authority": "authoritative",
            "approved": True,
            "publication_profile": (
                "exact"
                if require_exact_semantics
                else "validated"
                if require_validated
                else "portable"
            ),
            "project": project.name,
            "resolved_source": str(_resolve_workspace_source(config, root)),
            "targets": selected_targets,
            "policies": results,
            "compatible": compatible,
            "verified": verified,
            "native_validation_complete": native_validation_complete,
            "assurance_summary": assurance_summary,
            "product": provenance,
        }
        generated.mkdir(parents=True, exist_ok=True)
        if not compatible:
            failure_name = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            failure_root = generated / "failures" / failure_name
            if staging.exists():
                shutil.copytree(staging, failure_root)
            report["promoted"] = False
            current_path = generated / "current.json"
            if current_path.is_file():
                current = json.loads(current_path.read_text(encoding="utf-8"))
                report["preserved_current_bundle"] = current.get("bundle_digest")
            report["failure_report"] = str(failure_root / "compilation-report.json")
            _write_json_atomic(failure_root / "compilation-report.json", report)
            _write_json_atomic(generated / "last-attempt.json", report)
            return report

        contract_index = {
            str(item["tool"]): {
                target: (f"{item['tool']}/{target}/integration-contract.json")
                for target in item["targets"]
            }
            for item in results
        }
        _write_json_atomic(staging / "integration-contracts.json", contract_index)
        (staging / "CONSUMER.md").write_text(
            "\n".join(
                [
                    "# Consuming this policy bundle",
                    "",
                    "1. Resolve this bundle only through `generated/current.json`.",
                    "2. Verify bundle integrity before loading artifacts.",
                    "3. Read `integration-contracts.json` for target entrypoints.",
                    "4. Hydrate trusted context independently of model output.",
                    "5. Treat resolver, verifier, or engine failures as deny.",
                    "",
                    "The installed package includes the OPA reference consumer:",
                    "`policy-author evaluate-current <workspace> <tool> "
                    "--context <context.json>`.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        bundle_payload = {
            "schema_version": "policyauthor.dev/publication/v1alpha1",
            "authority": "authoritative",
            "approved": True,
            "product": {
                **provenance,
                "dirty_acknowledged": bool(
                    provenance["dirty"] is True and allow_dirty_product
                ),
            },
            "project": project.name,
            "source_revision": source_revision,
            "targets": selected_targets,
            "publication_profile": report["publication_profile"],
            "approvals": approvals,
            "validation": {
                "compatible": compatible,
                "verified": verified,
                "native_validation_complete": native_validation_complete,
                "assurance_summary": assurance_summary,
                "policies": results,
            },
            "artifacts": _artifact_entries(staging),
        }
        manifest = {
            **bundle_payload,
            "bundle_digest": _json_digest(_bundle_identity_payload(bundle_payload)),
            "compiled_at": datetime.now(UTC).isoformat(),
        }
        manifest["manifest_digest"] = _json_digest(manifest)
        (staging / "publication-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        bundle_name = str(manifest["bundle_digest"]).removeprefix("sha256:")
        bundle_root = generated / "bundles" / bundle_name
        if not bundle_root.exists():
            bundle_root.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(staging, bundle_root)
        verify_publication_bundle(bundle_root)
        replacements = [
            (
                bundle_root / str(item["tool"]),
                generated / str(item["tool"]),
            )
            for item in results
        ]
        _replace_directories_atomically(
            replacements,
            lambda: _write_json_atomic(
                generated / "current.json",
                {
                    "authority": "authoritative",
                    "bundle_digest": manifest["bundle_digest"],
                    "bundle": str(bundle_root.relative_to(generated)),
                },
            ),
        )
        report["bundle_digest"] = manifest["bundle_digest"]
        report["bundle"] = str(bundle_root)
        report["promoted"] = True
        _write_json_atomic(generated / "compilation-report.json", report)
        _write_json_atomic(generated / "last-attempt.json", report)
        return report
