# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import policy_authoring.cli as cli_module
from policy_authoring import __version__
from policy_authoring.cli import _edit_policy, app


def test_version_command() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_cli_source_is_ascii_safe_for_windows_consoles() -> None:
    source = Path(cli_module.__file__).read_text(encoding="utf-8")

    assert source.isascii()


def test_compile_draft_is_explicitly_unapproved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
) -> None:
    monkeypatch.setenv("POLICY_AUTHOR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("POLICY_AUTHOR_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    runner = CliRunner()
    project_path = project_root / "examples" / "document-update" / "project.yaml"
    policy_path = tmp_path / "policy.yaml"

    imported = runner.invoke(app, ["import-project", str(project_path)])
    assert imported.exit_code == 0, imported.output
    synthesized = runner.invoke(
        app,
        [
            "synthesize",
            "document-update",
            "apply_update",
            "--output",
            str(policy_path),
        ],
    )
    assert synthesized.exit_code == 0, synthesized.output

    compiled = runner.invoke(
        app,
        [
            "compile-draft",
            "document-update",
            str(policy_path),
            "--targets",
            "opa",
        ],
    )

    assert compiled.exit_code == 0, compiled.output
    assert "Draft artifacts are unapproved" in compiled.output
    manifest_path = (
        tmp_path
        / "artifacts"
        / "drafts"
        / "document-update"
        / "apply-update-policy"
        / "1"
        / "opa"
        / "draft-manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["authority"] == "draft"
    assert manifest["approved"] is False
    assert manifest["review_status"] == "needs_review"
    assert not (manifest_path.parent / "publication-manifest.json").exists()

    legacy = runner.invoke(
        app,
        [
            "compile",
            "document-update",
            str(policy_path),
            "--targets",
            "opa",
        ],
    )
    assert legacy.exit_code == 0, legacy.output
    assert "compile command is deprecated" in legacy.output


def test_cli_has_no_server_or_ambiguous_compile_command() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    assert "compile-draft" in result.output
    assert "compile-workspace" in result.output
    assert "export-policy" in result.output
    assert "serve" not in result.output


def test_discover_command_writes_project_artifacts(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "@tool\ndef archive_record(record_id: str) -> dict:\n"
        '    """Archive a record."""\n',
        encoding="utf-8",
    )
    runner = CliRunner()

    result = runner.invoke(app, ["discover", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = tmp_path / ".policy-authoring"
    assert (output / "project.yaml").is_file()
    assert (output / "context-contract.yaml").is_file()
    assert (output / "functional-gates.yaml").is_file()
    assert (output / "discovery-report.json").is_file()
    assert (output / "unresolved-questions.yaml").is_file()
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["tools_discovered"] == 1
    assert report["summary"]["unresolved_questions"] == 1
    assert "CAPABILITY DISCOVERY" in result.output
    assert '"summary":' not in result.output


def test_evaluate_engines_generate_only_for_source_file(
    tmp_path: Path,
    project_root: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "evaluate-engines",
            str(project_root / "examples" / "discovery-agent" / "agent.py"),
            "--tool",
            "apply_update",
            "--targets",
            "opa",
            "--generate-only",
            "--output",
            str(tmp_path / "evaluation"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "evaluation" / "proposed-policy.yaml").is_file()


def test_analyze_succeeds_when_no_tools_are_configured(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> None:\n    pass\n",
        encoding="utf-8",
    )
    output = tmp_path / "analysis"

    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(
        (output / "action-control-report.json").read_text(encoding="utf-8")
    )
    assert report["overall_status"] == "not_applicable"
    assert report["inventory"]["total_tools"] == 0
    assert "ACTION CONTROL ANALYSIS" in result.output
    assert "DISCOVER" in result.output
    assert '"inventory":' not in result.output


def test_analyze_json_prints_machine_report(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> None:\n    pass\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(source),
            "--targets",
            "opa",
            "--json",
            "--output",
            str(tmp_path / "analysis"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["overall_status"] == "not_applicable"
    assert payload["inventory"]["total_tools"] == 0


def test_analyze_uses_terminal_colors(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> None:\n    pass\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(tmp_path / "analysis"),
        ],
        color=True,
    )

    assert result.exit_code == 0, result.output
    assert "\x1b[" in result.output
    assert "\x1b[36m" in result.output
    assert "\x1b[32m" in result.output
    assert "ACTION CONTROL ANALYSIS" in result.output
    assert "NOT_APPLICABLE" in result.output


def test_analyze_document_update_applies_schema_gate(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source = project_root / "examples" / "document-update"
    output = tmp_path / "analysis"

    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    verification = json.loads(
        (
            output
            / "03-enforce"
            / "apply_update"
            / "canonical-verification.json"
        ).read_text(encoding="utf-8")
    )
    assert len(verification) == 11
    assert all(item["passed"] for item in verification)
    unknown = next(
        item for item in verification if item["scenario"] == "unknown-argument"
    )
    assert unknown["actual"] == "deny"
    assert unknown["evaluation_stage"] == "schema_validation"
    assert not unknown["policy_evaluated"]
    assert unknown["matched_rule_ids"] == ["validate-apply-update-schema"]
    valid = next(item for item in verification if item["scenario"] == "valid-action")
    assert valid["evaluation_stage"] == "policy"
    assert valid["policy_evaluated"]


def test_policy_workspace_cli_flow(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    pass\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / ".agent-policy"
    runner = CliRunner()

    initialized = runner.invoke(
        app,
        [
            "init",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(workspace),
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    assert "POLICY WORKSPACE CREATED" in initialized.output
    reviewed = runner.invoke(app, ["review", str(workspace)])
    assert reviewed.exit_code == 0, reviewed.output
    assert "agent.py:" in reviewed.output
    tested = runner.invoke(app, ["test-workspace", str(workspace)])
    assert tested.exit_code == 0, tested.output
    preview = runner.invoke(app, ["approval-preview", str(workspace)])
    assert preview.exit_code == 0, preview.output
    packet = json.loads(
        (workspace / "approval-packet.json").read_text(encoding="utf-8")
    )
    approved = runner.invoke(
        app,
        [
            "approve",
            str(workspace),
            "--tool",
            "all",
            "--reviewer",
            "reviewer@example.com",
            "--rationale",
            "Reviewed generated rules and passing tests.",
            "--confirm-snapshot",
            packet["confirmation_digest"],
        ],
    )
    assert approved.exit_code == 0, approved.output
    compiled = runner.invoke(
        app,
        ["compile-workspace", str(workspace)],
    )
    assert compiled.exit_code == 0, compiled.output
    assert "opa=validated[native]" in compiled.output
    assert "Native validation for every target: yes" in compiled.output
    artifact = (
        workspace / "generated" / "update_record" / "opa" / "policy" / "source-map.json"
    )
    assert artifact.is_file()
    current = json.loads(
        (workspace / "generated" / "current.json").read_text(encoding="utf-8")
    )
    bundle = workspace / "generated" / current["bundle"]
    verified = runner.invoke(app, ["verify-bundle", str(bundle)])
    assert verified.exit_code == 0, verified.output
    assert "BUNDLE INTEGRITY VERIFIED" in verified.output
    assert "Assurance mix: native=1" in verified.output
    archive = tmp_path / "exports" / "update-record-opa.zip"
    exported = runner.invoke(
        app,
        [
            "export-policy",
            str(workspace),
            "update_record",
            "--target",
            "opa",
            "--output",
            str(archive),
        ],
    )
    assert exported.exit_code == 0, exported.output
    assert "POLICY PACKAGE EXPORTED" in exported.output
    assert archive.is_file()

    artifact.write_text(
        artifact.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    still_verified = runner.invoke(app, ["verify-bundle", str(bundle)])
    assert still_verified.exit_code == 0, still_verified.output

    bundle_artifact = next(
        path
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "publication-manifest.json"
    )
    bundle_artifact.write_text(
        bundle_artifact.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    rejected = runner.invoke(app, ["verify-bundle", str(bundle)])
    assert rejected.exit_code == 2
    assert "artifact hashes do not match" in rejected.output
    assert "Traceback" not in rejected.output


def test_packet_disposition_remains_current_through_compilation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def create_order():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'create_order', 'Create an order', 'procurement', True, True,\n"
        " create_order, schema(['vendor_id'], vendor_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / ".agent-policy"
    runner = CliRunner()
    initialized = runner.invoke(
        app,
        [
            "init",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(workspace),
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    tested = runner.invoke(app, ["test-workspace", str(workspace)])
    assert tested.exit_code == 0, tested.output

    finding = "missing_reachable_approval_check"
    preview = runner.invoke(
        app,
        [
            "approval-preview",
            str(workspace),
            "--finding-disposition",
            (
                f"{finding}=false_positive:"
                "Static discovery cannot observe the host approval check."
            ),
            "--finding-evidence",
            f"{finding}=src://host/approval.py:42",
        ],
    )
    assert preview.exit_code == 0, preview.output
    packet_path = workspace / "approval-packet.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    approved = runner.invoke(
        app,
        [
            "approve",
            str(workspace),
            "--packet",
            str(packet_path),
            "--reviewer",
            "reviewer@example.com",
            "--reviewer-role",
            "service-owner",
            "--rationale",
            "Reviewed host approval evidence and passing policy tests.",
            "--confirm-snapshot",
            packet["confirmation_digest"],
        ],
    )
    assert approved.exit_code == 0, approved.output
    reviewed = runner.invoke(app, ["review", str(workspace)])
    assert reviewed.exit_code == 0, reviewed.output
    assert "Approved packet digests:" in reviewed.output
    monkeypatch.setattr(
        "policy_authoring.workspace.service.product_provenance",
        lambda: {
            "name": "agent-policy-author",
            "version": __version__,
            "commit": "abc123",
            "dirty": True,
            "packaged": True,
        },
    )
    rejected = runner.invoke(app, ["compile-workspace", str(workspace)])
    assert rejected.exit_code == 2, rejected.output
    assert "dirty source provenance" in rejected.output
    compiled = runner.invoke(
        app,
        [
            "compile-workspace",
            str(workspace),
            "--allow-dirty-product",
        ],
    )
    assert compiled.exit_code == 0, compiled.output
    assert "LOCAL BUNDLE PROMOTED" in compiled.output
    current = json.loads(
        (workspace / "generated" / "current.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (
            workspace
            / "generated"
            / current["bundle"]
            / "publication-manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["product"]["dirty"] is True
    assert manifest["product"]["dirty_acknowledged"] is True


def test_low_level_command_errors_do_not_expose_tracebacks(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "project.yaml"
    malformed.write_text("name: [", encoding="utf-8")

    result = CliRunner().invoke(app, ["import-project", str(malformed)])

    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output


def test_model_validation_errors_are_concise(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source = project_root / "examples" / "document-update" / "project.yaml"
    project = yaml.safe_load(source.read_text(encoding="utf-8"))
    project["tools"].append(project["tools"][0])
    malformed = tmp_path / "project.yaml"
    malformed.write_text(
        yaml.safe_dump(project, sort_keys=False),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["import-project", str(malformed)])

    assert result.exit_code == 2
    assert "duplicate tool name" in result.output
    assert "validation error for" not in result.output
    assert "errors.pydantic.dev" not in result.output
    assert "input_value=" not in result.output


def test_init_requires_explicit_empty_discovery_opt_out(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> None:\n    pass\n",
        encoding="utf-8",
    )
    strict_workspace = tmp_path / "strict-workspace"
    allowed_workspace = tmp_path / "allowed-workspace"
    runner = CliRunner()

    strict = runner.invoke(
        app,
        ["init", str(source), "--output", str(strict_workspace)],
    )
    allowed = runner.invoke(
        app,
        [
            "init",
            str(source),
            "--output",
            str(allowed_workspace),
            "--allow-no-actions",
        ],
    )

    assert strict.exit_code == 2, strict.output
    assert "no supported agent actions were discovered" in strict.output
    assert not strict_workspace.exists()
    assert allowed.exit_code == 0, allowed.output
    assert "Actions inventoried:" in allowed.output
    assert (allowed_workspace / "policy-author.yaml").is_file()


def test_workbench_initializes_tests_and_reports_next_actions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    pass\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"

    result = CliRunner().invoke(
        app,
        [
            "workbench",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(workspace),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "POLICY WORKBENCH" in result.output
    assert "NEEDS_REVIEW" in result.output
    assert "tests 4/4" in result.output
    assert "policy-author approve" in result.output
    report = json.loads(
        (workspace / "workbench-report.json").read_text(encoding="utf-8")
    )
    assert report["workspace_created"]
    assert report["readiness"] == "needs_review"
    assert report["tests"]["status"] == "passed"
    assert report["policies"][0]["source"]["path"] == "agent.py"
    gated = CliRunner().invoke(
        app,
        [
            "workbench",
            str(workspace),
            "--no-interactive",
            "--require-ready",
        ],
    )
    assert gated.exit_code == 1, gated.output
    assert "NEEDS_REVIEW" in gated.output


@pytest.mark.parametrize(
    "invalid_policy",
    [
        "rules: [\n",
        (
            "api_version: policyauthor.dev/v1alpha1\n"
            "kind: ActionPolicy\n"
            "metadata:\n"
            "  name: update-record-policy\n"
            "  version: 1\n"
            "  description: Missing required tool field\n"
            "  review_status: needs_review\n"
            "tool_schema_version: '1'\n"
            "interception_point: pre_tool_call\n"
            "default_decision: deny\n"
            "source_targets: []\n"
            "rules: []\n"
        ),
    ],
)
def test_edit_policy_rejects_invalid_yaml_or_schema_and_restores_last_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_policy: str,
) -> None:
    workspace = tmp_path / "workspace"
    policy_path = workspace / "policies" / "update_record.yaml"
    policy_path.parent.mkdir(parents=True)
    original_policy = (
        "api_version: policyauthor.dev/v1alpha1\n"
        "kind: ActionPolicy\n"
        "metadata:\n"
        "  name: update-record-policy\n"
        "  version: 1\n"
        "  description: Last valid policy\n"
        "  review_status: needs_review\n"
        "tool: update_record\n"
        "tool_schema_version: '1'\n"
        "interception_point: pre_tool_call\n"
        "default_decision: deny\n"
        "source_targets: []\n"
        "rules: []\n"
    )
    policy_path.write_text(original_policy, encoding="utf-8")

    def write_invalid_policy(path: str) -> int:
        Path(path).write_text(invalid_policy, encoding="utf-8")
        return 0

    responses = iter(["", "b"])
    monkeypatch.setattr("policy_authoring.cli.typer.launch", write_invalid_policy)
    monkeypatch.setattr(
        "policy_authoring.cli.typer.prompt",
        lambda *args, **kwargs: next(responses),
    )

    assert not _edit_policy(workspace, "update_record")
    assert policy_path.read_text(encoding="utf-8") == original_policy


def test_workbench_requires_explicit_empty_discovery_opt_out(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> None:\n    pass\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    runner = CliRunner()

    strict = runner.invoke(
        app,
        ["workbench", str(source), "--output", str(workspace)],
    )
    allowed = runner.invoke(
        app,
        ["workbench", str(workspace), "--allow-no-actions"],
    )

    assert strict.exit_code == 1, strict.output
    assert "NOT_APPLICABLE" in strict.output
    assert allowed.exit_code == 0, allowed.output


def test_test_workspace_prints_failed_case_details(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    runner = CliRunner()
    initialized = runner.invoke(
        app,
        [
            "init",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(workspace),
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    test_path = workspace / "tests" / "update_record.yaml"
    document = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    document["cases"][0]["expected_decision"] = (
        "allow"
        if document["cases"][0]["expected_decision"] != "allow"
        else "deny"
    )
    test_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["test-workspace", str(workspace)])

    assert result.exit_code == 1, result.output
    assert f"Failed {document['cases'][0]['id']}:" in result.output
    assert "expected" in result.output
    assert "actual" in result.output
    assert "matched rules:" in result.output


def test_approval_preview_prints_required_acknowledgement_flags(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    runner = CliRunner()
    initialized = runner.invoke(
        app,
        [
            "init",
            str(source),
            "--targets",
            "cedar",
            "--output",
            str(workspace),
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    policy_path = workspace / "policies" / "update_record.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    allow_rule = next(
        rule for rule in policy["rules"] if rule["decision"] == "allow"
    )
    allow_rule["decision"] = "warn"
    policy_path.write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )
    test_path = workspace / "tests" / "update_record.yaml"
    tests = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    for case in tests["cases"]:
        if case["expected_decision"] == "allow":
            case["expected_decision"] = "warn"
    test_path.write_text(
        yaml.safe_dump(tests, sort_keys=False),
        encoding="utf-8",
    )
    tested = runner.invoke(app, ["test-workspace", str(workspace)])
    assert tested.exit_code == 0, tested.output

    preview = runner.invoke(app, ["approval-preview", str(workspace)])

    assert preview.exit_code == 0, preview.output
    assert "Required semantic acknowledgements:" in preview.output
    assert "--acknowledge-lossy cedar:" in preview.output
    assert "same --acknowledge-lossy flags" in preview.output
    packet = json.loads(
        (workspace / "approval-packet.json").read_text(encoding="utf-8")
    )
    acknowledgements = packet["required_semantic_acknowledgements"]
    preview_args = ["approval-preview", str(workspace)]
    for acknowledgement in acknowledgements:
        preview_args.extend(["--acknowledge-lossy", acknowledgement])
    acknowledged_preview = runner.invoke(app, preview_args)
    assert acknowledged_preview.exit_code == 0, acknowledged_preview.output
    packet = json.loads(
        (workspace / "approval-packet.json").read_text(encoding="utf-8")
    )
    approval_args = [
        "approve",
        str(workspace),
        "--reviewer",
        "reviewer@example.com",
        "--reviewer-role",
        "service-owner",
        "--rationale",
        "Reviewed the fail-closed target translation.",
        "--confirm-snapshot",
        packet["confirmation_digest"],
        "--packet",
        str(workspace / "approval-packet.json"),
    ]
    approved = runner.invoke(app, approval_args)
    assert approved.exit_code == 0, approved.output

    exact = runner.invoke(
        app,
        [
            "compile-workspace",
            str(workspace),
            "--require-exact-semantics",
        ],
    )

    assert exact.exit_code == 1, exact.output
    assert "cedar: exact semantics required" in exact.output
    assert "allow-valid-action (lossy_fail_closed)" in exact.output


def test_workbench_recognizes_current_approval(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    pass\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize = CliRunner().invoke(
        app,
        [
            "workbench",
            str(source),
            "--targets",
            "opa",
            "--output",
            str(workspace),
        ],
    )
    assert initialize.exit_code == 0, initialize.output
    preview = CliRunner().invoke(app, ["approval-preview", str(workspace)])
    assert preview.exit_code == 0, preview.output
    packet = json.loads(
        (workspace / "approval-packet.json").read_text(encoding="utf-8")
    )
    approved = CliRunner().invoke(
        app,
        [
            "approve",
            str(workspace),
            "--reviewer",
            "reviewer@example.com",
            "--rationale",
            "Reviewed policy and passing tests.",
            "--confirm-snapshot",
            packet["confirmation_digest"],
        ],
    )
    assert approved.exit_code == 0, approved.output

    result = CliRunner().invoke(app, ["workbench", str(workspace)])
    gated = CliRunner().invoke(
        app,
        [
            "workbench",
            str(workspace),
            "--no-interactive",
            "--require-ready",
        ],
    )

    assert result.exit_code == 0, result.output
    assert gated.exit_code == 0, gated.output
    assert "Policies are ready to compile." in result.output
    report = json.loads(
        (workspace / "workbench-report.json").read_text(encoding="utf-8")
    )
    assert not report["workspace_created"]
    assert report["readiness"] == "passed"
    assert report["policies"][0]["approval_current"]
    assert report["next_commands"] == [
        f'policy-author compile-workspace "{workspace.resolve()}"'
    ]


def test_approve_requires_attributable_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / ".agent-policy"
    workspace.mkdir()
    (workspace / "policy-author.yaml").write_text(
        "project: example\nsource_root: .\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["approve", str(workspace)])

    assert result.exit_code == 2
    assert "--reviewer is required" in result.output
