# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from policy_authoring.domain.models import FindingDisposition
from policy_authoring.workspace import approve_workspace as approve_workspace_service
from policy_authoring.workspace import (
    build_approval_packet,
    compile_workspace,
    initialize_workspace,
    refresh_workspace,
    verify_publication_bundle,
)
from policy_authoring.workspace import service as workspace_service
from policy_authoring.workspace import test_workspace as run_workspace_tests


def _write_agent(path: Path) -> None:
    path.write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def mutate():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "def create_order():\n"
        "    mutate()\n"
        "SPECS = [ToolSpec(\n"
        "    'create_order', 'Create an order', 'procurement',\n"
        "    True, True, create_order,\n"
        "    schema(['vendor_id'], vendor_id='string'),\n"
        ")]\n",
        encoding="utf-8",
    )


def _write_tool_inventory(path: Path, tools: list[str]) -> None:
    functions = "".join(f"def {tool}():\n    pass\n" for tool in tools)
    registrations = ",\n".join(
        "ToolSpec(\n"
        f"    '{tool}', '{tool.replace('_', ' ').title()}', 'operations',\n"
        f"    True, True, {tool},\n"
        "    schema(['resource_id'], resource_id='string'),\n"
        ")"
        for tool in tools
    )
    path.write_text(
        functions + f"SPECS = [\n{registrations}\n]\n",
        encoding="utf-8",
    )


def _resolved_finding() -> list[FindingDisposition]:
    return [
        FindingDisposition(
            finding_id="missing_reachable_approval_check",
            disposition="accepted_risk",
            rationale="Temporary risk accepted for isolated test coverage.",
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            evidence=["test://risk-record"],
            compensating_controls=["Host test blocks external execution."],
        )
    ]


def approve_workspace(path: Path, **kwargs: Any) -> int:
    packet = build_approval_packet(
        path,
        tool_name=kwargs.get("tool_name"),
        finding_dispositions=kwargs.get("finding_dispositions"),
        semantic_acknowledgements=kwargs.get("semantic_acknowledgements"),
    )
    kwargs.setdefault(
        "approval_packet_digest",
        packet["confirmation_digest"],
    )
    return approve_workspace_service(path, **kwargs)


def test_workspace_lifecycle_and_source_targets(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"

    review = initialize_workspace(
        source,
        workspace,
        targets=["opa", "agent-hooks"],
    )

    assert review.actions[0].review_status == "needs_review"
    assert any(
        "did not find a reachable approval check" in question
        for question in review.actions[0].questions
    )
    policy_path = workspace / "policies" / "create_order.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    assert policy["metadata"]["review_status"] == "needs_review"
    assert policy["source_targets"] == [
        {
            "path": "agent.py",
            "line": 11,
            "symbol": "create_order",
            "role": "tool_registration",
        }
    ]
    tests = run_workspace_tests(workspace)
    assert tests["passed"]
    with pytest.raises(ValueError, match="structured dispositions"):
        approve_workspace(
            workspace,
            tool_name="create_order",
            reviewer="reviewer@example.com",
            rationale="Reviewed generated rules and tests.",
        )
    assert (
        approve_workspace(
            workspace,
            tool_name="create_order",
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed generated rules and tests.",
            finding_dispositions=_resolved_finding(),
        )
        == 1
    )
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "passed"
    assert report["policies"][0]["approval_current"]

    compiled = compile_workspace(workspace)

    assert compiled["compatible"]
    assert compiled["verified"]
    assert compiled["assurance_summary"] == {"contract": 1, "native": 1}
    assert not compiled["native_validation_complete"]
    assert compiled["bundle_digest"].startswith("sha256:")
    bundle = Path(compiled["bundle"])
    assert verify_publication_bundle(bundle)["integrity_verified"]
    current = json.loads(
        (workspace / "generated" / "current.json").read_text(encoding="utf-8")
    )
    assert current["bundle_digest"] == compiled["bundle_digest"]
    export = workspace_service.export_policy_package(
        workspace,
        tool_name="create_order",
        target="opa",
        destination=tmp_path / "exports" / "create-order-opa",
    )
    exported_archive = Path(export["archive"])
    assert exported_archive.name == "create-order-opa.zip"
    assert exported_archive.is_file()
    assert export["bundle_digest"] == compiled["bundle_digest"]
    with zipfile.ZipFile(exported_archive) as package:
        names = set(package.namelist())
    assert any(name.endswith(".rego") for name in names)
    repeated = compile_workspace(workspace)
    assert repeated["bundle_digest"] == compiled["bundle_digest"]
    review_document = yaml.safe_load(
        (workspace / "review.yaml").read_text(encoding="utf-8")
    )
    approval = review_document["actions"][0]["approval"]
    assert approval["reviewer"] == "reviewer@example.com"
    assert approval["reviewer_role"] == "service-owner"
    assert approval["finding_dispositions"][0]["owner"] == "reviewer@example.com"
    assert approval["source_revision"]
    assert approval["policy_digest"].startswith("sha256:")
    assert approval["test_digest"].startswith("sha256:")
    source_map = json.loads(
        (
            workspace
            / "generated"
            / "create_order"
            / "opa"
            / "policy"
            / "source-map.json"
        ).read_text(encoding="utf-8")
    )
    assert source_map["applies_to"][0]["path"] == "agent.py"
    assert source_map["applies_to"][0]["symbol"] == "create_order"
    binding = json.loads(
        (
            workspace
            / "generated"
            / "create_order"
            / "agent-hooks"
            / "agent-hooks"
            / "binding.json"
        ).read_text(encoding="utf-8")
    )
    assert binding["spec"]["sourceTargets"][0]["path"] == "agent.py"
    referenced_opa = (
        workspace
        / "generated"
        / "create_order"
        / "agent-hooks"
        / "agent-hooks"
        / binding["spec"]["evaluator"]["artifact"]
    ).resolve()
    assert referenced_opa.is_file()


def test_jsonl_trace_changes_invalidate_workspace_evidence(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    trace = source / "agent-hooks-trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "spec": "agent-hooks/v1",
                "session": {"id": "session-1"},
                "sequence": 1,
                "interception_point": "pre_tool_call",
                "tool_call": {
                    "name": "create_order",
                    "args": {"vendor_id": "vendor-1"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing evidence.",
        finding_dispositions=_resolved_finding(),
    )

    trace.write_text(
        trace.read_text(encoding="utf-8").replace("vendor-1", "vendor-2"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="workspace discovery is stale"):
        compile_workspace(workspace)


def test_source_schema_changes_require_explicit_workspace_refresh(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    agent = source / "agent.py"
    _write_agent(agent)
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed initial schema and passing tests.",
        finding_dispositions=_resolved_finding(),
    )

    agent.write_text(
        agent.read_text(encoding="utf-8").replace(
            "schema(['vendor_id'], vendor_id='string')",
            (
                "schema(['vendor_id', 'region'], vendor_id='string', "
                "region=['westus2', 'eastus'])"
            ),
        ),
        encoding="utf-8",
    )

    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "needs_reconciliation"
    assert any(
        change["kind"] == "tool_changed"
        and change["tool"] == "create_order"
        and "input_schema" in change["fields"]
        for change in report["reconciliation"]["changes"]
    )
    with pytest.raises(ValueError, match="refresh-workspace"):
        run_workspace_tests(workspace)
    with pytest.raises(ValueError, match="refresh-workspace"):
        build_approval_packet(workspace)
    with pytest.raises(ValueError, match="refresh-workspace"):
        compile_workspace(workspace)

    refreshed = refresh_workspace(workspace)
    assert refreshed["applied"]
    project = yaml.safe_load(
        (workspace / "project.yaml").read_text(encoding="utf-8")
    )
    schema = project["tools"][0]["input_schema"]
    assert "region" in schema["required"]
    tests = yaml.safe_load(
        (workspace / "tests" / "create_order.yaml").read_text(encoding="utf-8")
    )
    assert all(
        "region" in case["context"]["action"]["arguments"]
        for case in tests["cases"]
    )
    review = yaml.safe_load(
        (workspace / "review.yaml").read_text(encoding="utf-8")
    )
    assert review["actions"][0]["review_status"] == "needs_review"
    assert "approval" not in review["actions"][0]
    assert run_workspace_tests(workspace)["passed"]
    packet = build_approval_packet(
        workspace,
        finding_dispositions=_resolved_finding(),
    )
    reconciliation_findings = [
        finding
        for finding in packet["policies"][0]["blocking_findings"]
        if finding.startswith("reconciliation-create-order-")
    ]
    assert len(reconciliation_findings) == 1
    with pytest.raises(ValueError, match="unresolved findings"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed the refreshed policy without resolving suggestions.",
            finding_dispositions=_resolved_finding(),
        )
    reconciliation_disposition = FindingDisposition(
        finding_id=reconciliation_findings[0],
        disposition="accepted_risk",
        rationale="The new region control is deferred for isolated test coverage.",
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        evidence=["test://reconciliation-review"],
        compensating_controls=["The host restricts region values before execution."],
    )
    assert (
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed and dispositioned reconciliation suggestions.",
            finding_dispositions=[
                *_resolved_finding(),
                reconciliation_disposition,
            ],
        )
        == 1
    )
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "passed"
    assert report["policies"][0]["approval_current"]
    compiled = compile_workspace(workspace)
    assert compiled["promoted"]
    assert verify_publication_bundle(Path(compiled["bundle"]))["integrity_verified"]


def test_unknown_action_risk_blocks_workspace_readiness(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "tools.json").write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "frobnicate_session",
                        "description": "Perform a session operation.",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "session_id": {"type": "string"},
                            },
                            "required": ["session_id"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    workspace = tmp_path / ".agent-policy"

    review = initialize_workspace(source, workspace, targets=["opa"])
    assert review.actions[0].review_status == "needs_review"
    assert "unclassified_action_risk" in review.actions[0].blocking_findings
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "failed"
    assert report["policies"][0]["tests"]["status"] == "blocked"
    with pytest.raises(ValueError, match="unclassified action risk"):
        run_workspace_tests(workspace)
    with pytest.raises(ValueError, match="unclassified action risk"):
        build_approval_packet(workspace)


def test_refresh_manages_added_and_removed_tools_without_overwriting_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    agent = source / "agent.py"
    _write_tool_inventory(agent, ["create_order"])
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])

    policy_path = workspace / "policies" / "create_order.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["rules"][0]["reason"] = "Developer-authored reason retained across refresh."
    policy_path.write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )

    _write_tool_inventory(agent, ["create_order", "cancel_order"])
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "needs_reconciliation"
    assert any(
        item["kind"] == "tool_added" and item["tool"] == "cancel_order"
        for item in report["reconciliation"]["changes"]
    )
    added = refresh_workspace(workspace)
    assert added["applied"]
    refreshed = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    assert (
        refreshed["rules"][0]["reason"]
        == "Developer-authored reason retained across refresh."
    )
    assert (workspace / "policies" / "cancel_order.yaml").is_file()
    assert (workspace / "tests" / "cancel_order.yaml").is_file()

    _write_tool_inventory(agent, ["cancel_order"])
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "needs_reconciliation"
    assert any(
        item["kind"] == "tool_removed" and item["tool"] == "create_order"
        for item in report["reconciliation"]["changes"]
    )
    removed = refresh_workspace(workspace)
    assert removed["applied"]
    assert not policy_path.exists()
    assert (
        workspace
        / ".artifacts"
        / "retired"
        / "policies"
        / "create_order.yaml"
    ).is_file()
    assert (
        workspace
        / ".artifacts"
        / "retired"
        / "tests"
        / "create_order.yaml"
    ).is_file()


def test_publication_bundle_detects_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing test evidence.",
        finding_dispositions=_resolved_finding(),
    )
    report = compile_workspace(workspace)
    bundle = Path(report["bundle"])
    artifact = next(
        path
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "publication-manifest.json"
    )
    artifact.write_text(
        artifact.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="artifact hashes"):
        verify_publication_bundle(bundle)


def test_compile_requires_policy_approval(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])

    try:
        compile_workspace(workspace)
    except ValueError as exc:
        assert "approve it" in str(exc)
    else:
        raise AssertionError("draft policy compilation should require review")


def test_workspace_requires_at_least_one_target(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")

    with pytest.raises(ValueError, match="at least 1 item"):
        initialize_workspace(source, tmp_path / ".agent-policy", targets=[])


def test_empty_tests_fail_and_cannot_be_approved(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    test_path = workspace / "tests" / "create_order.yaml"
    test_path.write_text("tool: create_order\ncases: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match="at least one test case"):
        run_workspace_tests(workspace)
    with pytest.raises(ValueError, match="run test-workspace"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            rationale="This must not be accepted.",
        )


def test_failed_or_stale_tests_block_approval_and_compilation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    test_path = workspace / "tests" / "create_order.yaml"
    document = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    document["cases"][0]["expected_decision"] = "deny"
    test_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )

    result = run_workspace_tests(workspace)
    assert not result["passed"]
    with pytest.raises(ValueError, match="nonempty and passing"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            rationale="This must not be accepted.",
            finding_dispositions=_resolved_finding(),
        )

    document["cases"][0]["expected_decision"] = "allow"
    test_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing test evidence.",
        finding_dispositions=_resolved_finding(),
    )
    test_path.write_text(
        test_path.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="approval is stale"):
        compile_workspace(workspace)


def test_workspace_tests_fail_closed_for_incompatible_comparison(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])

    policy_path = workspace / "policies" / "create_order.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["default_decision"] = "allow"
    policy["rules"] = [
        {
            "id": "malformed-ordered-comparison",
            "decision": "allow",
            "reason": "Exercise incompatible runtime operand handling.",
            "condition": {
                "operator": "greater_than_or_equal",
                "left": {"path": "action.arguments.vendor_id"},
                "right": {"literal": 123},
            },
        }
    ]
    policy_path.write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )

    result = run_workspace_tests(workspace)

    assert not result["passed"]
    case = result["results"][0]["cases"][0]
    assert case["expected"] == "allow"
    assert case["actual"] == "deny"
    assert not case["passed"]
    assert case["matched_rule_ids"] == []
    assert case["reason"].startswith(
        "rule_evaluation_error:malformed-ordered-comparison:"
    )


def test_workspace_inside_source_is_excluded_from_source_revision(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = source / "policy-workspace"
    initialize_workspace(source, workspace, targets=["opa"])

    assert run_workspace_tests(workspace)["passed"]
    assert (
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed passing test evidence.",
            finding_dispositions=_resolved_finding(),
        )
        == 1
    )
    assert compile_workspace(workspace)["compatible"]


@pytest.mark.parametrize(
    ("file_name", "stale_label"),
    [
        ("project.yaml", "project"),
        ("context.yaml", "context"),
        ("policy-author.yaml", "workspace configuration"),
    ],
)
def test_approval_binds_workspace_inputs(
    tmp_path: Path,
    file_name: str,
    stale_label: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed all approval-bound inputs.",
        finding_dispositions=_resolved_finding(),
    )
    bound_file = workspace / file_name
    bound_file.write_text(
        bound_file.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=stale_label):
        compile_workspace(workspace)


def test_approval_binds_findings_adapters_product_and_target_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed all approval-bound inputs.",
        finding_dispositions=_resolved_finding(),
    )

    with pytest.raises(ValueError, match="outside workspace approval scope"):
        compile_workspace(workspace, targets=["opa", "cedar"])

    review_path = workspace / "review.yaml"
    review_text = review_path.read_text(encoding="utf-8")
    review_document = yaml.safe_load(review_text)
    review_document["actions"][0]["blocking_findings"].append("new_governance_finding")
    review_path.write_text(
        yaml.safe_dump(review_document, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="findings"):
        compile_workspace(workspace)
    review_path.write_text(review_text, encoding="utf-8")

    original = workspace_service._adapter_identities
    monkeypatch.setattr(
        workspace_service,
        "_adapter_identities",
        lambda targets: {
            **original(targets),
            "opa": "opa@changed",
        },
    )
    with pytest.raises(ValueError, match="adapter identities"):
        compile_workspace(workspace)
    monkeypatch.setattr(workspace_service, "_adapter_identities", original)

    monkeypatch.setattr(workspace_service, "__version__", "changed")
    with pytest.raises(ValueError, match="product version"):
        compile_workspace(workspace)


def test_failed_compilation_preserves_last_known_good_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing evidence.",
        finding_dispositions=_resolved_finding(),
    )
    accepted = compile_workspace(workspace)
    current_path = workspace / "generated" / "current.json"
    current_before = current_path.read_text(encoding="utf-8")
    convenience = (
        workspace / "generated" / "create_order" / "opa" / "policy" / "source-map.json"
    )
    convenience_before = convenience.read_bytes()
    monkeypatch.setattr(
        workspace_service,
        "validate_target",
        lambda target, root: {
            "status": "failed",
            "detail": "forced validation failure",
        },
    )

    failed = compile_workspace(workspace)

    assert not failed["compatible"]
    assert current_path.read_text(encoding="utf-8") == current_before
    assert convenience.read_bytes() == convenience_before
    assert Path(accepted["bundle"]).is_dir()
    assert list((workspace / "generated" / "failures").iterdir())


def test_pointer_failure_rolls_back_all_convenience_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["agent-hooks", "opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing evidence.",
        finding_dispositions=_resolved_finding(),
    )
    compile_workspace(workspace)
    current_path = workspace / "generated" / "current.json"
    current_before = current_path.read_bytes()
    views = {
        path: path.read_bytes()
        for path in (workspace / "generated" / "create_order").rglob("*")
        if path.is_file()
    }
    original_write = workspace_service._write_json_atomic

    def fail_current(path: Path, value: object) -> None:
        if path.name == "current.json":
            raise OSError("forced pointer failure")
        original_write(path, value)

    monkeypatch.setattr(
        workspace_service,
        "_write_json_atomic",
        fail_current,
    )

    with pytest.raises(OSError, match="forced pointer failure"):
        compile_workspace(workspace)

    assert current_path.read_bytes() == current_before
    assert {
        path: path.read_bytes()
        for path in (workspace / "generated" / "create_order").rglob("*")
        if path.is_file()
    } == views


def test_workspace_source_binding_survives_checkout_move(
    tmp_path: Path,
) -> None:
    original = tmp_path / "original"
    source = original / "source"
    source.mkdir(parents=True)
    _write_agent(source / "agent.py")
    workspace = original / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    before = run_workspace_tests(workspace)

    moved = tmp_path / "moved"
    shutil.copytree(original, moved)
    shutil.rmtree(original)
    moved_workspace = moved / ".agent-policy"
    moved_source = moved / "source"
    moved_agent = moved_source / "agent.py"
    moved_agent.write_text(
        moved_agent.read_text(encoding="utf-8") + "\n# moved checkout\n",
        encoding="utf-8",
    )

    after = run_workspace_tests(moved_workspace)

    assert after["resolved_source"] == str(moved_source.resolve())
    assert after["source_revision"] != before["source_revision"]


def test_subset_publication_removes_stale_convenience_targets(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(
        source,
        workspace,
        targets=["opa", "agent-hooks", "acs"],
    )
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing evidence and target contracts.",
        finding_dispositions=_resolved_finding(),
    )
    compile_workspace(workspace)
    view = workspace / "generated" / "create_order"
    assert {path.name for path in view.iterdir()} == {
        "opa",
        "agent-hooks",
        "acs",
    }

    subset = compile_workspace(workspace, targets=["opa"])

    assert subset["promoted"]
    assert {path.name for path in view.iterdir()} == {"opa"}
    bundle_tool = Path(subset["bundle"]) / "create_order"
    assert {path.relative_to(view) for path in view.rglob("*") if path.is_file()} == {
        path.relative_to(bundle_tool)
        for path in bundle_tool.rglob("*")
        if path.is_file()
    }


def test_approval_requires_current_packet_confirmation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]

    with pytest.raises(ValueError, match="approval-preview"):
        approve_workspace_service(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed passing evidence.",
            finding_dispositions=_resolved_finding(),
        )

    packet = build_approval_packet(
        workspace,
        finding_dispositions=_resolved_finding(),
    )
    attributed_disposition = _resolved_finding()
    attributed_disposition[0] = attributed_disposition[0].model_copy(
        update={"owner": "reviewer@example.com"}
    )
    attributed_packet = build_approval_packet(
        workspace,
        finding_dispositions=attributed_disposition,
    )
    assert attributed_packet["confirmation_digest"] == packet["confirmation_digest"]
    changed_disposition = _resolved_finding()
    changed_disposition[0] = changed_disposition[0].model_copy(
        update={
            "rationale": ("Temporary risk accepted with newly documented evidence.")
        }
    )
    with pytest.raises(ValueError, match="approval packet changed"):
        approve_workspace_service(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed passing evidence.",
            finding_dispositions=changed_disposition,
            approval_packet_digest=packet["confirmation_digest"],
        )


def test_expired_accepted_risk_invalidates_existing_approval(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed temporary risk acceptance.",
        finding_dispositions=_resolved_finding(),
    )
    review_path = workspace / "review.yaml"
    review = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    review["actions"][0]["approval"]["finding_dispositions"][0]["expires_at"] = (
        "2000-01-01T00:00:00Z"
    )
    review_path.write_text(
        yaml.safe_dump(review, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="accepted-risk disposition expired"):
        compile_workspace(workspace)


def test_lossy_semantics_require_acknowledgement_and_exact_profile_rejects(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["cedar"])
    policy_path = workspace / "policies" / "create_order.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["rules"][0]["decision"] = "warn"
    policy_path.write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )
    test_path = workspace / "tests" / "create_order.yaml"
    tests = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    for case in tests["cases"]:
        if case["expected_decision"] == "allow":
            case["expected_decision"] = "warn"
    test_path.write_text(
        yaml.safe_dump(tests, sort_keys=False),
        encoding="utf-8",
    )
    initial_results = run_workspace_tests(workspace)
    actual_by_id = {
        case["id"]: case["actual"] for case in initial_results["results"][0]["cases"]
    }
    tests = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    for case in tests["cases"]:
        case["expected_decision"] = actual_by_id[case["id"]]
    test_path.write_text(
        yaml.safe_dump(tests, sort_keys=False),
        encoding="utf-8",
    )
    assert run_workspace_tests(workspace)["passed"]

    with pytest.raises(ValueError, match="require acknowledgement"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed lossy fail-closed translation.",
            finding_dispositions=_resolved_finding(),
        )

    packet = build_approval_packet(
        workspace,
        finding_dispositions=_resolved_finding(),
    )
    acknowledgements = packet["required_semantic_acknowledgements"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed lossy fail-closed translation.",
        finding_dispositions=_resolved_finding(),
        semantic_acknowledgements=acknowledgements,
    )
    report = compile_workspace(workspace, require_exact_semantics=True)

    assert not report["compatible"]
    assert report["publication_profile"] == "exact"
    assert not report["promoted"]


def test_integrity_verification_distinguishes_incomplete_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed passing evidence.",
        finding_dispositions=_resolved_finding(),
    )
    monkeypatch.setattr(
        workspace_service,
        "validate_target",
        lambda target, root: {
            "status": "validation_not_run",
            "detail": "validator intentionally unavailable",
            "assurance": "native",
            "validator": {
                "name": target,
                "version": None,
                "result_digest": "sha256:not-run",
            },
        },
    )
    report = compile_workspace(workspace)
    bundle = Path(report["bundle"])

    verified = verify_publication_bundle(bundle)
    assert verified["integrity_verified"]
    assert not verified["fully_validated"]
    with pytest.raises(ValueError, match="validation is incomplete"):
        verify_publication_bundle(bundle, require_validated=True)


def test_finding_dispositions_require_substantive_governance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_agent(source / "agent.py")
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]

    resolved = FindingDisposition(
        finding_id="missing_reachable_approval_check",
        disposition="resolved",
        rationale="The active finding was reviewed as remediated.",
    )
    with pytest.raises(ValueError, match="cannot be marked resolved"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed the active finding.",
            finding_dispositions=[resolved],
        )

    false_positive = FindingDisposition(
        finding_id="missing_reachable_approval_check",
        disposition="false_positive",
        rationale="Static discovery cannot observe the host approval check.",
        evidence=["src://host/approval.py:42"],
    )
    with pytest.raises(ValueError, match="require --reviewer-role"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            rationale="Reviewed host approval evidence.",
            finding_dispositions=[false_positive],
        )

    no_evidence = false_positive.model_copy(update={"evidence": []})
    with pytest.raises(ValueError, match="require evidence"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed host approval evidence.",
            finding_dispositions=[no_evidence],
        )

    assert (
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed host approval evidence.",
            finding_dispositions=[false_positive],
        )
        == 1
    )
    report = workspace_service.build_workbench_report(workspace)
    assert report["readiness"] == "passed"
    assert report["policies"][0]["approval_current"]
    compiled = compile_workspace(workspace)
    assert compiled["promoted"]

    expired = _resolved_finding()[0].model_copy(
        update={"expires_at": datetime(2000, 1, 1, tzinfo=UTC)}
    )
    with pytest.raises(ValueError, match="future timezone-aware"):
        approve_workspace(
            workspace,
            reviewer="reviewer@example.com",
            reviewer_role="service-owner",
            rationale="Reviewed temporary risk acceptance.",
            finding_dispositions=[expired],
        )


def test_policy_with_only_nonallow_rules_can_be_approved(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "def update_record():\n"
        "    pass\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / ".agent-policy"
    review = initialize_workspace(source, workspace, targets=["opa"])
    assert "incomplete_policy_synthesis" in review.actions[0].blocking_findings
    policy_path = workspace / "policies" / "update_record.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["rules"] = [
        {
            "id": "deny-blocked-record",
            "decision": "deny",
            "reason": "Blocked records must never be updated.",
            "condition": {
                "operator": "equals",
                "left": {"path": "action.arguments.record_id"},
                "right": {"literal": "blocked"},
            },
        },
        {
            "id": "escalate-review-record",
            "decision": "escalate",
            "reason": "Review records require an external decision.",
            "condition": {
                "operator": "equals",
                "left": {"path": "action.arguments.record_id"},
                "right": {"literal": "review"},
            },
        },
    ]
    policy_path.write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )
    test_path = workspace / "tests" / "update_record.yaml"
    test_path.write_text(
        yaml.safe_dump(
            {
                "tool": "update_record",
                "cases": [
                    {
                        "id": "deny-blocked",
                        "description": "Explicit deny rule matches.",
                        "context": {
                            "action": {
                                "tool": "update_record",
                                "arguments": {"record_id": "blocked"},
                            }
                        },
                        "expected_decision": "deny",
                    },
                    {
                        "id": "escalate-review",
                        "description": "Explicit escalation rule matches.",
                        "context": {
                            "action": {
                                "tool": "update_record",
                                "arguments": {"record_id": "review"},
                            }
                        },
                        "expected_decision": "escalate",
                    },
                    {
                        "id": "default-deny",
                        "description": "No rule matches, so the default applies.",
                        "context": {
                            "action": {
                                "tool": "update_record",
                                "arguments": {"record_id": "ordinary"},
                            }
                        },
                        "expected_decision": "deny",
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    assert run_workspace_tests(workspace)["passed"]
    report = workspace_service.build_workbench_report(workspace)
    assert report["policies"][0]["rule_count"] == 2
    assert report["policies"][0]["unresolved_findings"] == []
    assert report["policies"][0]["approval_eligible"]
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed the deny and escalation outcomes.",
    )
    assert workspace_service.build_workbench_report(workspace)["policies"][0][
        "approval_current"
    ]
