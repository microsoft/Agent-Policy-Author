# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from policy_authoring.analysis import run_action_control_analysis, workflow
from policy_authoring.discovery import discover_project


def test_constructor_registry_and_authoritative_metadata(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "def schema(required=None, **properties):\n"
        "    return {}\n"
        "def create_order():\n"
        "    pass\n"
        "SPECS = [ToolSpec(\n"
        "    'create_order', 'Create an order', 'procurement',\n"
        "    True, True, create_order,\n"
        "    schema(['vendor_id'], vendor_id='string'),\n"
        ")]\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert len(report.project.tools) == 1
    tool = report.project.tools[0]
    assert tool.name == "create_order"
    assert tool.mutates_state is True
    assert tool.requires_approval is True
    assert tool.risk == "consequential-write"
    assert tool.input_schema["required"] == ["vendor_id"]
    assert len(report.proposals) == 1
    assert report.proposals[0].policy.rules


def test_three_outcome_workflow_generates_all_mutating_policies(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def mutate():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "def update_record():\n"
        "    mutate()\n"
        "def delete_record():\n"
        "    mutate()\n"
        "SPECS = [\n"
        " ToolSpec('update_record', 'Update record', 'records', True, False,\n"
        "          update_record, schema(['record_id'], record_id='string')),\n"
        " ToolSpec('delete_record', 'Delete record', 'records', True, False,\n"
        "          delete_record, schema(['record_id'], record_id='string')),\n"
        "]\n",
        encoding="utf-8",
    )

    report = run_action_control_analysis(
        source,
        tmp_path / "output",
        targets=["opa"],
        verify_native=False,
    )

    assert [phase.phase for phase in report.phases] == [
        "discover",
        "identify",
        "enforce",
    ]
    assert report.inventory.total_tools == 2
    assert report.control_analysis.coverage.policies_generated == 2
    assert report.control_analysis.coverage.policies_with_rules == 2
    assert report.control_analysis.coverage.scenarios_generated > 0
    assert report.control_analysis.gaps
    assert len(report.enforcement) == 2
    assert all(item.rule_count > 0 for item in report.enforcement)
    assert all(item.scenario_count > 0 for item in report.enforcement)
    assert report.overall_status == "needs_review"
    persisted = json.loads(
        (tmp_path / "output" / "action-control-report.json").read_text(encoding="utf-8")
    )
    assert persisted["phases"][0]["phase"] == "discover"


def test_repository_without_tools_is_not_applicable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text(
        "def main() -> str:\n    return 'no agent tools configured'\n",
        encoding="utf-8",
    )

    report = run_action_control_analysis(
        source,
        tmp_path / "output",
        targets=["opa"],
        verify_native=False,
    )

    assert report.inventory.total_tools == 0
    assert report.control_analysis.requirements == []
    assert report.enforcement == []
    assert report.overall_status == "not_applicable"
    assert [phase.status for phase in report.phases] == [
        "passed",
        "not_applicable",
        "not_applicable",
    ]


def test_native_engine_error_is_reported_without_aborting_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    monkeypatch.setattr(
        workflow,
        "evaluate_codebase",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("engine request failed")
        ),
    )

    report = run_action_control_analysis(
        source,
        tmp_path / "output",
        targets=["opa"],
        verify_native=True,
    )

    assert report.overall_status == "failed"
    error = json.loads(
        (
            tmp_path / "output" / "03-enforce" / "update_record" / "native-error.json"
        ).read_text(encoding="utf-8")
    )
    assert error["status"] == "engine_error"
    assert error["detail"] == "engine request failed"
