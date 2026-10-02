# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from policy_authoring.runtime import consumer
from policy_authoring.workspace import (
    approve_workspace,
    build_approval_packet,
    compile_workspace,
    initialize_workspace,
)
from policy_authoring.workspace import test_workspace as run_workspace_tests


def _published_workspace(tmp_path: Path) -> Path:
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
    workspace = tmp_path / ".agent-policy"
    initialize_workspace(source, workspace, targets=["opa"])
    assert run_workspace_tests(workspace)["passed"]
    packet = build_approval_packet(workspace)
    approve_workspace(
        workspace,
        reviewer="reviewer@example.com",
        reviewer_role="service-owner",
        rationale="Reviewed policy, tests, and runtime contract.",
        approval_packet_digest=packet["confirmation_digest"],
    )
    assert compile_workspace(workspace)["promoted"]
    return workspace


def test_reference_consumer_evaluates_current_opa_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _published_workspace(tmp_path)
    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.shutil.which",
        lambda name: "opa",
    )
    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout=json.dumps(
                {
                    "result": [
                        {
                            "expressions": [
                                {
                                    "value": {
                                        "decision": "allow",
                                        "matched_rule_ids": ["allow-valid"],
                                        "reason": "test",
                                    }
                                }
                            ]
                        }
                    ]
                }
            ),
            stderr="",
        ),
    )

    result = consumer.evaluate_current_opa(
        workspace,
        "update_record",
        {
            "action": {
                "tool": "update_record",
                "arguments": {"record_id": "1"},
            }
        },
    )

    assert result["decision"] == "allow"


def test_reference_consumer_rejects_schema_invalid_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _published_workspace(tmp_path)
    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.shutil.which",
        lambda name: "opa",
    )

    with pytest.raises(
        RuntimeError,
        match="violate the reviewed tool schema.*unexpected_admin",
    ):
        consumer.evaluate_current_opa(
            workspace,
            "update_record",
            {
                "action": {
                    "tool": "update_record",
                    "arguments": {
                        "record_id": "1",
                        "unexpected_admin": True,
                    },
                }
            },
        )


def test_reference_consumer_rejects_mismatched_action_tool(
    tmp_path: Path,
) -> None:
    workspace = _published_workspace(tmp_path)

    with pytest.raises(RuntimeError, match="action.tool must equal"):
        consumer.evaluate_current_opa(
            workspace,
            "update_record",
            {
                "action": {
                    "tool": "delete_record",
                    "arguments": {"record_id": "1"},
                }
            },
        )


def test_reference_consumer_fails_closed_on_missing_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _published_workspace(tmp_path)
    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.shutil.which",
        lambda name: None,
    )

    with pytest.raises(RuntimeError, match="decision is deny"):
        consumer.evaluate_current_opa(
            workspace,
            "update_record",
            {
                "action": {
                    "tool": "update_record",
                    "arguments": {"record_id": "1"},
                }
            },
        )


def test_reference_consumer_rejects_tampered_current_bundle(
    tmp_path: Path,
) -> None:
    workspace = _published_workspace(tmp_path)
    current = json.loads(
        (workspace / "generated" / "current.json").read_text(encoding="utf-8")
    )
    bundle = workspace / "generated" / current["bundle"]
    artifact = next(
        path
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "publication-manifest.json"
    )
    artifact.write_text(
        artifact.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="verification failed.*decision is deny"):
        consumer.evaluate_current_opa(
            workspace,
            "update_record",
            {
                "action": {
                    "tool": "update_record",
                    "arguments": {"record_id": "1"},
                }
            },
        )


def test_reference_consumer_fails_closed_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _published_workspace(tmp_path)
    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.shutil.which",
        lambda name: "opa",
    )

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="opa", timeout=1)

    monkeypatch.setattr(
        "policy_authoring.runtime.consumer.subprocess.run",
        timeout,
    )

    with pytest.raises(RuntimeError, match="timed out.*decision is deny"):
        consumer.evaluate_current_opa(
            workspace,
            "update_record",
            {
                "action": {
                    "tool": "update_record",
                    "arguments": {"record_id": "1"},
                }
            },
            timeout=1,
        )
