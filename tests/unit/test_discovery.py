# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from policy_authoring.discovery import DiscoveryLimits, discover_project


def test_discovers_python_tools_and_agent_hooks_traces(
    project_root: Path,
) -> None:
    root = project_root / "examples" / "discovery-agent"

    report = discover_project(root, allowed_roots=(project_root,))

    tools = {tool.name: tool for tool in report.project.tools}
    assert set(tools) == {
        "apply_update",
        "confirm_update",
        "prepare_update",
    }
    assert tools["apply_update"].risk == "consequential-write"
    assert tools["apply_update"].input_schema["properties"]["route"]["enum"] == [
        "primary",
        "shadow",
    ]
    assert tools["prepare_update"].risk == "write"
    assert report.summary.traces_imported == 1
    assert report.summary.context_attributes >= 6
    assert not report.questions
    assert len(report.proposals) == 1
    proposal = report.proposals[0]
    assert proposal.target_tool == "apply_update"
    assert "restrict-route" in {item.id for item in proposal.recommendations}
    assert {gate.stage for gate in proposal.functional_gates} == {
        "schema_validation",
        "trusted_context",
        "approval",
        "operation_binding",
        "policy_decision",
        "execution",
    }


def test_discovers_a_single_source_file(project_root: Path) -> None:
    path = project_root / "examples" / "discovery-agent" / "agent.py"

    report = discover_project(path, allowed_roots=(path.parent,))

    assert report.project.name == "agent"
    assert {tool.name for tool in report.project.tools} == {
        "apply_update",
        "confirm_update",
        "prepare_update",
    }
    assert report.summary.files_scanned == 1
    assert report.summary.traces_imported == 0


def test_discovers_openapi_operations(tmp_path: Path) -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Example", "version": "1"},
        "paths": {
            "/records/{record_id}": {
                "get": {
                    "operationId": "get_record",
                    "parameters": [
                        {
                            "name": "record_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                },
                "delete": {
                    "operationId": "delete_record",
                    "parameters": [
                        {
                            "name": "record_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                },
            }
        },
    }
    (tmp_path / "openapi.json").write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    tools = {tool.name: tool for tool in report.project.tools}

    assert tools["get_record"].risk == "read"
    assert tools["delete_record"].risk == "consequential-write"
    assert report.summary.unresolved_questions == 0


def test_rejects_path_outside_allowed_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    with pytest.raises(ValueError, match="outside allowed roots"):
        discover_project(outside, allowed_roots=(allowed,))


def test_imports_json_schema_tool_manifest(tmp_path: Path) -> None:
    manifest = {
        "tools": [
            {
                "name": "send_notification",
                "description": "Send a notification to an external recipient.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "message": {"type": "string"},
                    },
                    "required": ["recipient", "message"],
                },
            }
        ]
    }
    (tmp_path / "tools.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert report.project.tools[0].name == "send_notification"
    assert report.project.tools[0].risk == "consequential-write"
    assert report.summary.unresolved_questions == 0


def test_deploy_actions_are_consequential_and_keep_atomic_source_reference(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "@tool\n"
        "def deploy_release(version: str) -> dict:\n"
        '    """Deploy a release."""\n',
        encoding="utf-8",
    )
    (tmp_path / "tools.json").write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "deploy_release",
                        "description": "Deploy a release.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"version": {"type": "string"}},
                            "required": ["version"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    tool = report.project.tools[0]

    assert tool.risk == "consequential-write"
    assert tool.source_path == "tools.json"
    assert tool.source_line is None


@pytest.mark.parametrize(
    "name",
    [
        "revoke_session",
        "disable_account",
        "suspend_subscription",
        "terminate_job",
    ],
)
def test_additional_consequential_verbs_are_classified(
    tmp_path: Path,
    name: str,
) -> None:
    (tmp_path / "tools.json").write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": name,
                        "description": f"{name.replace('_', ' ')}.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"id": {"type": "string"}},
                            "required": ["id"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert report.project.tools[0].risk == "consequential-write"
    assert report.summary.unresolved_questions == 0


def test_rejects_malformed_supported_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "tools.json"
    manifest.write_text(
        '{"tools": [{"name": "broken", "inputSchema":',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=r"tools\.json:1:\d+: malformed supported JSON manifest",
    ):
        discover_project(tmp_path, allowed_roots=(tmp_path,))


def test_rejects_malformed_agent_hooks_jsonl_with_line_number(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "@tool\ndef archive_record(record_id: str) -> dict:\n"
        '    """Archive a record."""\n',
        encoding="utf-8",
    )
    trace = tmp_path / "agent-hooks-trace.jsonl"
    trace.write_text(
        '{"spec":"agent-hooks/v1","interception_point":"pre_tool_call"}\n'
        "{not-json}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=(
            r"agent-hooks-trace\.jsonl:2:2: malformed supported "
            r"Agent Hooks JSONL trace"
        ),
    ):
        discover_project(tmp_path, allowed_roots=(tmp_path,))


def test_imports_existing_project_definition(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source = project_root / "examples" / "document-update" / "project.yaml"
    project = yaml.safe_load(source.read_text(encoding="utf-8"))
    project["name"] = "imported-project"
    (tmp_path / "project.yaml").write_text(
        yaml.safe_dump(project, sort_keys=False),
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert report.project.name == "imported-project"
    assert report.evidence[0].detail.startswith("Imported an existing")
    assert report.provenance.mode == "explicit_project"
    assert report.provenance.project_definition == "project.yaml"


def test_ignores_generated_and_dependency_directories(tmp_path: Path) -> None:
    ignored = [
        tmp_path / ".policy-authoring",
        tmp_path / ".agent-policy",
        tmp_path / ".action-control",
        tmp_path / "generated",
        tmp_path / ".venv",
        tmp_path / "node_modules",
    ]
    for directory in ignored:
        directory.mkdir()
        (directory / "tool.py").write_text(
            "@tool\ndef delete_everything():\n    pass\n",
            encoding="utf-8",
        )
    (tmp_path / "agent.py").write_text(
        "@tool\ndef get_status():\n    pass\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert [tool.name for tool in report.project.tools] == ["get_status"]
    assert report.summary.files_scanned == 1
    assert report.provenance.mode == "source_scan"


def test_nested_generated_project_does_not_override_live_source(
    tmp_path: Path,
    project_root: Path,
) -> None:
    generated = tmp_path / "nested" / "output"
    generated.mkdir(parents=True)
    project = yaml.safe_load(
        (project_root / "examples" / "document-update" / "project.yaml").read_text(
            encoding="utf-8"
        )
    )
    project["name"] = "stale-generated-project"
    (generated / "project.yaml").write_text(
        yaml.safe_dump(project, sort_keys=False),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "@tool\ndef get_status():\n    pass\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert report.project.name != "stale-generated-project"
    assert [tool.name for tool in report.project.tools] == ["get_status"]
    assert report.provenance.mode == "source_scan"


def test_enforces_file_limit(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"tool_{index}.py").write_text(
            "@tool\ndef get_value(value: str):\n    pass\n",
            encoding="utf-8",
        )

    with pytest.raises(ValueError, match="exceeded 2 files"):
        discover_project(
            tmp_path,
            allowed_roots=(tmp_path,),
            limits=DiscoveryLimits(max_files=2),
        )


def test_control_evidence_does_not_merge_repeated_nested_names(
    tmp_path: Path,
) -> None:
    (tmp_path / "base.py").write_text(
        "def mutate(action):\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    action()\n"
        "    record_mutation()\n",
        encoding="utf-8",
    )
    (tmp_path / "approved.py").write_text(
        "def approved_handler():\n"
        "    def action():\n"
        "        check_approval()\n"
        "    mutate(action)\n"
        "SPECS = [ToolSpec('approved', 'Approved write', 'test', True, True,\n"
        " approved_handler, schema())]\n",
        encoding="utf-8",
    )
    (tmp_path / "unapproved.py").write_text(
        "def unapproved_handler():\n"
        "    def action():\n"
        "        perform_write()\n"
        "    mutate(action)\n"
        "SPECS = [ToolSpec('unapproved', 'Unapproved write', 'test', True,\n"
        " True, unapproved_handler, schema())]\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    approvals = {
        item.target_tool
        for item in report.project.controls
        if item.kind == "approval_binding"
    }

    assert approvals == {"approved"}
