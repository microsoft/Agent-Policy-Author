# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from policy_authoring.evaluation import cross_engine, evaluate_codebase


def _native_engines_unavailable() -> bool:
    if any(shutil.which(name) is None for name in ("opa", "cedar", "docker")):
        return True
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return True
    return completed.returncode != 0


native_engines = pytest.mark.skipif(
    _native_engines_unavailable(),
    reason=(
        "OPA, Cedar, and an available Docker daemon are required for native "
        "engine evaluation"
    ),
)


@pytest.mark.native_engines
@native_engines
def test_cross_engine_evaluation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    report = evaluate_codebase(
        project_root / "examples" / "discovery-agent",
        tmp_path / "evaluation",
        tool_name="apply_update",
        cerbos_port=13594,
    )

    assert report.all_passed
    assert len(report.scenarios) == 11
    assert len(report.results) == 66
    assert {item.target for item in report.results} == {
        "canonical",
        "opa",
        "cedar",
        "cerbos",
        "agent-hooks+opa",
        "acs+opa",
    }
    assert all(
        item.side_effect_executed
        for item in report.results
        if item.scenario == "valid-action"
    )
    assert not any(
        item.side_effect_executed
        for item in report.results
        if item.scenario != "valid-action"
    )
    assert (tmp_path / "evaluation" / "evaluation-report.json").is_file()
    assert (tmp_path / "evaluation" / "evaluation-evidence.json").is_file()


def test_generate_only_accepts_single_source_file(
    tmp_path: Path,
    project_root: Path,
) -> None:
    report = evaluate_codebase(
        project_root / "examples" / "discovery-agent" / "agent.py",
        tmp_path / "generated",
        tool_name="apply_update",
        targets=["opa"],
        generate_only=True,
    )

    assert not report.all_passed
    assert report.compilation_status == "passed"
    assert report.evaluation_status == "not_run"
    assert report.overall_status == "partial"
    assert not report.evaluation_performed
    assert report.requested_targets == ["opa"]
    assert report.results == []
    assert report.compilation == {"opa": True}
    evidence = json.loads(
        (tmp_path / "generated" / "evaluation-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    assert evidence["product_version"]
    assert evidence["requested_targets"] == ["opa"]


def test_cedar_process_errors_are_not_policy_denies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "policy.cedar"
    schema = tmp_path / "schema.json"
    policy.write_text("", encoding="utf-8")
    schema.write_text(
        '{"":{"actions":{"tool":{"appliesTo":{"context":'
        '{"type":"Record","attributes":{}}}}}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cross_engine,
        "_run",
        lambda *args, **kwargs: CompletedProcess(
            args=[],
            returncode=1,
            stdout="failed to parse request\n",
            stderr="request schema mismatch\n",
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="failed before a policy decision",
    ):
        cross_engine._cedar_decision(
            "cedar",
            policy,
            schema,
            {},
            "tool",
            tmp_path,
        )


def test_cedar_deny_exit_code_is_a_valid_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "policy.cedar"
    schema = tmp_path / "schema.json"
    policy.write_text("", encoding="utf-8")
    schema.write_text(
        '{"":{"actions":{"tool":{"appliesTo":{"context":'
        '{"type":"Record","attributes":{}}}}}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cross_engine,
        "_run",
        lambda *args, **kwargs: CompletedProcess(
            args=[],
            returncode=1,
            stdout="DENY\n",
            stderr="",
        ),
    )

    decision = cross_engine._cedar_decision(
        "cedar",
        policy,
        schema,
        {},
        "tool",
        tmp_path,
    )

    assert decision.decision == "deny"


def test_missing_rule_attribution_fails_expected_rule_match() -> None:
    scenario = cross_engine.EvaluationScenario(
        id="missing-attribution",
        description="Expected rule attribution is required",
        context={},
        expected_decision="deny",
        expected_rule_ids=["required-rule", "second-required-rule"],
    )

    result = cross_engine._result(
        scenario,
        "example",
        cross_engine.NativeDecision(
            decision="deny",
            matched_rule_ids=["required-rule"],
            detail="deny with incomplete attribution",
        ),
    )

    assert not result.passed


def test_warn_expectations_follow_target_capabilities() -> None:
    scenario = cross_engine.EvaluationScenario(
        id="warn",
        description="Warn behavior",
        context={},
        expected_decision="warn",
        expect_execution=True,
    )
    preserving = cross_engine._result(
        scenario,
        "opa",
        cross_engine.NativeDecision(
            decision="warn",
            detail="warn",
        ),
    )
    fail_closed = cross_engine._result(
        scenario,
        "cedar",
        cross_engine.NativeDecision(
            decision="deny",
            detail="lowered warn",
        ),
    )

    assert preserving.passed
    assert preserving.expected_effective_decision == "allow"
    assert fail_closed.passed
    assert fail_closed.expected_effective_decision == "deny"


def test_cerbos_extracts_matched_rule_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cross_engine,
        "_http_json",
        lambda *args, **kwargs: {
            "results": [
                {
                    "actions": {"apply_update": "EFFECT_DENY"},
                    "meta": {
                        "actions": {
                            "apply_update": {
                                "matchedPolicy": "apply-update-policy",
                                "matchedRules": [
                                    {"ruleName": "bind-digest"},
                                    {"ruleName": "restrict-route"},
                                ],
                            }
                        }
                    },
                }
            ]
        },
    )

    decision = cross_engine._cerbos_decision(
        "http://cerbos",
        {},
        "apply_update",
        1,
        "scenario",
    )

    assert decision.matched_rule_ids == ["bind-digest", "restrict-route"]


def test_native_command_timeout_is_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def time_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=["engine"], timeout=1)

    monkeypatch.setattr(subprocess, "run", time_out)

    with pytest.raises(RuntimeError, match="timed out"):
        cross_engine._run(["engine"], timeout=1)
