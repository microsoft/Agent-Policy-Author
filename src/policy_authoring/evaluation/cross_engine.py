# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

import yaml
from pydantic import Field

from policy_authoring import __version__
from policy_authoring.discovery import discover_project
from policy_authoring.domain.input_validation import (
    evaluate_effective_policy,
    validate_project_action_input,
)
from policy_authoring.domain.models import (
    CanonicalPolicy,
    FunctionalGate,
    ProjectDefinition,
    RunStatus,
    StrictModel,
)
from policy_authoring.ingestion.loader import dump_yaml
from policy_authoring.service import AuthoringService
from policy_authoring.storage.repository import Repository
from policy_authoring.testing.generator import (
    build_synthetic_context,
    generate_tests,
)


class EvaluationScenario(StrictModel):
    id: str
    description: str
    context: dict[str, Any]
    expected_decision: Literal["allow", "deny", "warn", "escalate"]
    expected_rule_ids: list[str] = Field(default_factory=list)
    expect_execution: bool = False


class NativeDecision(StrictModel):
    decision: Literal["allow", "deny", "warn", "escalate"]
    matched_rule_ids: list[str] = Field(default_factory=list)
    detail: str


class EngineCaseResult(StrictModel):
    scenario: str
    target: str
    expected_decision: Literal["allow", "deny", "warn", "escalate"]
    expected_effective_decision: Literal["allow", "deny"]
    native_decision: Literal["allow", "deny", "warn", "escalate"] | None
    effective_decision: Literal["allow", "deny"]
    matched_rule_ids: list[str] = Field(default_factory=list)
    side_effect_executed: bool
    passed: bool
    detail: str


class CrossEngineReport(StrictModel):
    project: str
    target_tool: str
    policy: CanonicalPolicy
    functional_gates: list[FunctionalGate]
    scenarios: list[EvaluationScenario]
    requested_targets: list[str]
    compilation: dict[str, bool]
    results: list[EngineCaseResult]
    evaluation_performed: bool
    compilation_status: RunStatus
    evaluation_status: RunStatus
    overall_status: RunStatus
    all_passed: bool


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _valid_context(
    project: ProjectDefinition,
    target_tool: str,
) -> dict[str, Any]:
    workflow: dict[str, Any] = {}
    arguments: dict[str, Any] | None = None
    for trace in project.traces:
        if trace.outcome != "success":
            continue
        for step in trace.steps:
            if step.type == "tool_result" and step.output is not None:
                if step.tool.startswith("prepare"):
                    workflow["prepared"] = deepcopy(step.output)
                elif step.tool.startswith("confirm"):
                    workflow["confirmation"] = deepcopy(step.output)
            elif step.type == "tool_call" and step.tool == target_tool:
                arguments = deepcopy(step.arguments or {})
                break
        if arguments is not None:
            break
    if arguments is None:
        raise ValueError(f"no successful trace invokes {target_tool}")
    return {
        "principal": {
            "user_id": "example-user",
            "tenant_id": "example-tenant",
        },
        "action": {
            "tool": target_tool,
            "arguments": arguments,
        },
        "workflow": workflow,
        "environment": {"name": "test"},
    }


def _scenario(
    base: dict[str, Any],
    identifier: str,
    description: str,
    expected: Literal["allow", "deny", "escalate"],
    *,
    expected_rule_ids: list[str] | None = None,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> EvaluationScenario:
    context = deepcopy(base)
    if mutate is not None:
        mutate(context)
    return EvaluationScenario(
        id=identifier,
        description=description,
        context=context,
        expected_decision=expected,
        expected_rule_ids=expected_rule_ids or [],
        expect_execution=expected in {"allow", "warn"},
    )


def build_scenarios(
    project: ProjectDefinition,
    target_tool: str,
    policy: CanonicalPolicy | None = None,
) -> list[EvaluationScenario]:
    try:
        base = _valid_context(project, target_tool)
    except ValueError:
        if policy is None:
            raise
        cases = generate_tests(
            policy,
            build_synthetic_context(project, target_tool),
        )
        return [
            EvaluationScenario(
                id=item.id,
                description=item.description,
                context=item.context,
                expected_decision=item.expected_decision,  # type: ignore[arg-type]
                expected_rule_ids=(
                    [item.id.removeprefix("violate-")]
                    if item.id.startswith("violate-")
                    else []
                ),
                expect_execution=item.expected_decision in {"allow", "warn"},
            )
            for item in cases
            if item.expected_decision in {"allow", "deny", "warn", "escalate"}
        ]

    def set_argument(
        name: str,
        value: Any,
    ) -> Callable[[dict[str, Any]], None]:
        return lambda context: context["action"]["arguments"].__setitem__(
            name,
            value,
        )

    def remove_confirmation(context: dict[str, Any]) -> None:
        context["workflow"].pop("confirmation", None)
        prepared = context["workflow"].get("prepared")
        if isinstance(prepared, dict) and "operation_id" in prepared:
            context["runtime"] = {
                "tool_context": {
                    "operation_id": prepared["operation_id"],
                }
            }

    def set_confirmation(
        name: str,
        value: Any,
    ) -> Callable[[dict[str, Any]], None]:
        return lambda context: context["workflow"]["confirmation"].__setitem__(
            name,
            value,
        )

    def remove_prepared(context: dict[str, Any]) -> None:
        context["workflow"].pop("prepared", None)

    def add_unknown_argument(context: dict[str, Any]) -> None:
        context["action"]["arguments"]["unreviewed_override"] = True

    scenarios = [
        _scenario(
            base,
            "valid-action",
            "Prepared and confirmed action with unchanged arguments",
            "allow",
        ),
        _scenario(
            base,
            "unknown-argument",
            "Tool call contains an argument absent from the discovered schema",
            "deny",
            expected_rule_ids=[f"validate-{target_tool.replace('_', '-')}-schema"],
            mutate=add_unknown_argument,
        ),
    ]
    arguments = base.get("action", {}).get("arguments", {})
    argument_scenarios = {
        "digest": (
            "digest-mutation",
            "Tool-call digest differs from prepared state",
            "bind-digest",
            "__mutated_digest__",
        ),
        "value": (
            "value-mutation",
            "Tool-call value differs from prepared state",
            "bind-value",
            "__mutated_value__",
        ),
        "document_id": (
            "document-mutation",
            "Tool-call document differs from prepared state",
            "bind-document-id",
            "__other_document__",
        ),
        "route": (
            "route-shift",
            "Tool call uses an unobserved route allowed by the broad schema",
            "restrict-route",
            "shadow",
        ),
    }
    if isinstance(arguments, dict):
        for name, (
            identifier,
            description,
            rule_id,
            value,
        ) in argument_scenarios.items():
            if name in arguments:
                scenarios.insert(
                    -1,
                    _scenario(
                        base,
                        identifier,
                        description,
                        "deny",
                        expected_rule_ids=[rule_id],
                        mutate=set_argument(name, value),
                    ),
                )
    workflow = base.get("workflow")
    if isinstance(workflow, dict):
        confirmation = workflow.get("confirmation")
        if isinstance(confirmation, dict):
            scenarios.insert(
                -1,
                _scenario(
                    base,
                    "skipped-confirmation",
                    "Confirmation evidence is absent",
                    "escalate",
                    mutate=remove_confirmation,
                ),
            )
            confirmation_scenarios: list[
                tuple[
                    str,
                    str,
                    str,
                    Literal["deny", "escalate"],
                    str,
                    Any,
                ]
            ] = [
                (
                    "confirmed",
                    "negative-confirmation",
                    "Confirmation exists but explicitly records false",
                    "escalate",
                    "require-positive-confirm-update",
                    False,
                ),
                (
                    "operation_id",
                    "cross-operation-confirmation",
                    "Confirmation belongs to a different operation",
                    "deny",
                    "bind-confirmation-operation-id",
                    "__other_operation__",
                ),
                (
                    "digest",
                    "replayed-confirmation",
                    "Confirmation digest belongs to an older prepared action",
                    "deny",
                    "bind-confirmation-digest",
                    "__old_digest__",
                ),
            ]
            for (
                name,
                identifier,
                description,
                expected,
                rule_id,
                value,
            ) in confirmation_scenarios:
                if name in confirmation:
                    scenarios.insert(
                        -1,
                        _scenario(
                            base,
                            identifier,
                            description,
                            expected,
                            expected_rule_ids=[rule_id],
                            mutate=set_confirmation(name, value),
                        ),
                    )
        if isinstance(workflow.get("prepared"), dict):
            scenarios.insert(
                -1,
                _scenario(
                    base,
                    "missing-trusted-state",
                    "Prepared state cannot be resolved by the host",
                    "deny",
                    mutate=remove_prepared,
                ),
            )
    return scenarios


def _effective(decision: str) -> Literal["allow", "deny"]:
    return "allow" if decision in {"allow", "warn"} else "deny"


def _native_policy_decision(
    decision: str,
) -> Literal["allow", "deny", "warn", "escalate"]:
    if decision in {"allow", "deny", "warn", "escalate"}:
        return decision  # type: ignore[return-value]
    raise ValueError(f"unsupported native evaluation decision: {decision}")


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"command timed out after {timeout:g}s: {' '.join(command)}"
        ) from exc


def _opa_decision(
    executable: str,
    policy_path: Path,
    query: str,
    context: dict[str, Any],
    work: Path,
) -> NativeDecision:
    input_path = work / "opa-input.json"
    _write_json(input_path, context)
    completed = _run(
        [
            executable,
            "eval",
            "--format=json",
            "--data",
            str(policy_path),
            "--input",
            str(input_path),
            query,
        ]
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    payload = json.loads(completed.stdout)
    value = payload["result"][0]["expressions"][0]["value"]
    evidence = value.get("evidence", {})
    matched_rule_ids = value.get("matched_rule_ids")
    if matched_rule_ids is None and isinstance(evidence, dict):
        matched_rule_ids = evidence.get("matched_rule_ids", [])
    return NativeDecision(
        decision=value["decision"],
        matched_rule_ids=matched_rule_ids or [],
        detail=value.get("reason", "OPA decision"),
    )


def _filter_cedar_record(
    value: dict[str, Any],
    schema: dict[str, Any],
) -> dict[str, Any]:
    attributes = schema.get("attributes", {})
    if not isinstance(attributes, dict):
        return {}
    filtered: dict[str, Any] = {}
    for name, attribute_schema in attributes.items():
        if name not in value or not isinstance(attribute_schema, dict):
            continue
        item = value[name]
        if attribute_schema.get("type") == "Record" and isinstance(item, dict):
            filtered[name] = _filter_cedar_record(item, attribute_schema)
        else:
            filtered[name] = deepcopy(item)
    return filtered


def _cedar_context(
    context: dict[str, Any],
    schema_path: Path,
    tool_name: str,
) -> dict[str, Any]:
    value = {
        key: deepcopy(item)
        for key, item in context.items()
        if key not in {"principal", "resource"}
    }
    action = value.get("action")
    if isinstance(action, dict):
        action.pop("tool", None)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    context_schema = schema[""]["actions"][tool_name]["appliesTo"]["context"]
    if not isinstance(context_schema, dict):
        raise RuntimeError("Cedar schema does not define a context record")
    return _filter_cedar_record(value, context_schema)


def _cedar_decision(
    executable: str,
    policy_path: Path,
    schema_path: Path,
    context: dict[str, Any],
    tool_name: str,
    work: Path,
) -> NativeDecision:
    context_path = work / "cedar-context.json"
    entities_path = work / "cedar-entities.json"
    _write_json(
        context_path,
        _cedar_context(context, schema_path, tool_name),
    )
    _write_json(entities_path, [])
    completed = _run(
        [
            executable,
            "authorize",
            "--principal",
            'Agent::"example-agent"',
            "--action",
            f'Action::"{tool_name}"',
            "--resource",
            f'ToolResource::"{tool_name}"',
            "--context",
            str(context_path),
            "--entities",
            str(entities_path),
            "--policies",
            str(policy_path),
            "--schema",
            str(schema_path),
            "--schema-format",
            "json",
            "--error-format",
            "plain",
            "--verbose",
        ]
    )
    output = "\n".join(item for item in (completed.stdout, completed.stderr) if item)
    first_line = next(
        (line.strip() for line in output.splitlines() if line.strip()),
        "",
    )
    if first_line not in {"ALLOW", "DENY"}:
        raise RuntimeError(
            f"Cedar evaluation for {tool_name} failed before a policy "
            "decision: "
            f"{output.strip() or 'unknown Cedar error'}"
        )
    decision: Literal["allow", "deny"] = "allow" if first_line == "ALLOW" else "deny"
    matched = re.findall(r"^\s{2}([a-z][a-z0-9-]+)\s*$", output, re.MULTILINE)
    return NativeDecision(
        decision=decision,
        matched_rule_ids=matched,
        detail=first_line,
    )


def _http_json(
    url: str,
    value: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = None if value is None else json.dumps(value).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if data is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{url} returned a non-object response")
    return payload


def _cerbos_decision(
    base_url: str,
    context: dict[str, Any],
    tool_name: str,
    policy_version: int,
    scenario_id: str,
) -> NativeDecision:
    payload = {
        "requestId": scenario_id,
        "includeMeta": True,
        "principal": {
            "id": "example-agent",
            "roles": ["agent"],
            "attr": {},
        },
        "resources": [
            {
                "resource": {
                    "kind": f"agent_tool_{tool_name}",
                    "policyVersion": str(policy_version),
                    "id": tool_name,
                    "attr": context,
                },
                "actions": [tool_name],
            }
        ],
    }
    response = _http_json(f"{base_url}/api/check/resources", payload)
    result = response["results"][0]
    effect = result["actions"][tool_name]
    matched = (
        result.get("meta", {})
        .get("actions", {})
        .get(tool_name, {})
        .get("matchedPolicy", "unknown")
    )
    metadata = result.get("meta", {}).get("actions", {}).get(tool_name, {})
    matched_rules = metadata.get("matchedRules", [])
    if not isinstance(matched_rules, list):
        raise RuntimeError("Cerbos returned invalid matchedRules metadata")
    matched_rule_ids = []
    for item in matched_rules:
        if not isinstance(item, dict) or not isinstance(item.get("ruleName"), str):
            raise RuntimeError("Cerbos returned a malformed matched rule")
        matched_rule_ids.append(item["ruleName"])
    return NativeDecision(
        decision="allow" if effect == "EFFECT_ALLOW" else "deny",
        matched_rule_ids=matched_rule_ids,
        detail=f"{effect}; matched policy {matched}",
    )


@contextmanager
def _cerbos_server(
    policy_directory: Path,
    work: Path,
    *,
    image: str,
    port: int,
) -> Iterator[str]:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker is required for native Cerbos evaluation")
    preflight = _run([docker, "info", "--format", "{{.ServerVersion}}"])
    if preflight.returncode != 0:
        raise RuntimeError(
            "Docker is installed but unavailable: "
            + (preflight.stderr.strip() or preflight.stdout.strip())
        )
    config = work / "cerbos-config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "server": {
                    "httpListenAddr": ":3592",
                    "grpcListenAddr": ":3593",
                },
                "storage": {
                    "driver": "disk",
                    "disk": {"directory": "/policies"},
                },
                "audit": {"enabled": False},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    name = f"policy-author-eval-{int(time.time() * 1000)}"
    completed = _run(
        [
            docker,
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "-e",
            "CERBOS_NO_TELEMETRY=1",
            "-p",
            f"127.0.0.1:{port}:3592",
            "-v",
            f"{policy_directory.resolve()}:/policies:ro",
            "-v",
            f"{config.resolve()}:/config/conf.yaml:ro",
            image,
            "server",
            "--config=/config/conf.yaml",
        ]
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    container_id = completed.stdout.strip()
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(30):
            try:
                health = _http_json(f"{base_url}/_cerbos/health")
                if health.get("status") == "SERVING":
                    break
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(0.5)
        else:
            logs = _run([docker, "logs", container_id])
            raise RuntimeError(f"Cerbos did not start: {logs.stderr}")
        yield base_url
    finally:
        _run([docker, "rm", "--force", container_id])


@contextmanager
def _no_cerbos() -> Iterator[None]:
    yield None


def _acs_context(context: dict[str, Any]) -> dict[str, Any]:
    policy_state = {
        key: deepcopy(value)
        for key, value in context.items()
        if key not in {"action", "principal", "resource"}
    }
    return {
        "policy_target": {
            "kind": "tool_args",
            "path": "$.tool_call.args",
            "value": deepcopy(context["action"]["arguments"]),
        },
        "snapshot": {
            "actor": deepcopy(context.get("principal", {})),
            "metadata": {"policy_authoring": policy_state},
            "tool_call": {
                "name": context["action"]["tool"],
                "args": deepcopy(context["action"]["arguments"]),
            },
        },
    }


def _result(
    scenario: EvaluationScenario,
    target: str,
    decision: NativeDecision,
) -> EngineCaseResult:
    expected = (
        "deny"
        if scenario.expected_decision == "warn" and target in {"cedar", "cerbos"}
        else _effective(scenario.expected_decision)
    )
    actual = _effective(decision.decision)
    executed = actual == "allow"
    rules_match = not scenario.expected_rule_ids or set(
        scenario.expected_rule_ids
    ).issubset(decision.matched_rule_ids)
    return EngineCaseResult(
        scenario=scenario.id,
        target=target,
        expected_decision=scenario.expected_decision,
        expected_effective_decision=expected,
        native_decision=decision.decision,
        effective_decision=actual,
        matched_rule_ids=decision.matched_rule_ids,
        side_effect_executed=executed,
        passed=(
            actual == expected and executed == (expected == "allow") and rules_match
        ),
        detail=decision.detail,
    )


def _schema_gate_result(
    scenario: EvaluationScenario,
    target: str,
    gate_id: str,
    detail: str,
) -> EngineCaseResult:
    expected = _effective(scenario.expected_decision)
    return EngineCaseResult(
        scenario=scenario.id,
        target=target,
        expected_decision=scenario.expected_decision,
        expected_effective_decision=expected,
        native_decision=None,
        effective_decision="deny",
        matched_rule_ids=[gate_id],
        side_effect_executed=False,
        passed=expected == "deny" and gate_id in scenario.expected_rule_ids,
        detail=f"Blocked by generated schema gate: {detail}",
    )


def _markdown(report: CrossEngineReport) -> str:
    lines = [
        "# Cross-engine policy evaluation",
        "",
        f"- Project: `{report.project}`",
        f"- Target tool: `{report.target_tool}`",
        f"- Overall status: `{report.overall_status}`",
        "",
        "| Scenario | Target | Native | Effective | Expected | Executed | Result |",
        "|---|---|---|---|---|---:|---|",
    ]
    for result in report.results:
        lines.append(
            "| "
            f"{result.scenario} | {result.target} | "
            f"{result.native_decision or 'gate'} | "
            f"{result.effective_decision} | {result.expected_decision} | "
            f"{str(result.side_effect_executed).lower()} | "
            f"{'PASS' if result.passed else 'FAIL'} |"
        )
    return "\n".join(lines) + "\n"


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _write_evaluation_evidence(
    destination: Path,
    report: CrossEngineReport,
    source: Path,
) -> None:
    evidence_files = [
        destination / name
        for name in (
            "discovery-report.json",
            "project.yaml",
            "proposed-policy.yaml",
            "functional-gates.yaml",
            "scenarios.json",
            "evaluation-report.json",
        )
        if (destination / name).is_file()
    ]
    _write_json(
        destination / "evaluation-evidence.json",
        {
            "schema_version": "policyauthor.dev/evaluation-evidence/v1alpha1",
            "product_version": __version__,
            "source": str(source),
            "project": report.project,
            "target_tool": report.target_tool,
            "requested_targets": report.requested_targets,
            "native_executables": {
                name: shutil.which(name) for name in ("opa", "cedar", "docker")
            },
            "artifacts": [
                {
                    "path": path.relative_to(destination).as_posix(),
                    "sha256": _sha256_file(path),
                }
                for path in evidence_files
            ],
        },
    )


def evaluate_codebase(
    project_path: Path,
    output: Path,
    *,
    tool_name: str | None = None,
    targets: list[str] | None = None,
    generate_only: bool = False,
    cerbos_image: str = "ghcr.io/cerbos/cerbos:0.46.0",
    cerbos_port: int = 13593,
) -> CrossEngineReport:
    source = project_path.resolve(strict=True)
    allowed_root = source if source.is_dir() else source.parent
    destination = output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    discovery = discover_project(source, allowed_roots=(allowed_root,))
    proposals = [
        proposal
        for proposal in discovery.proposals
        if tool_name is None or proposal.target_tool == tool_name
    ]
    if len(proposals) != 1:
        names = ", ".join(item.target_tool for item in discovery.proposals)
        raise ValueError(
            "select exactly one consequential tool; "
            f"available proposals: {names or 'none'}"
        )
    proposal = proposals[0]
    project = discovery.project
    policy = proposal.policy
    service = AuthoringService(
        Repository(destination / "evaluation.db"),
        destination / "artifacts",
    )
    service.import_project(project)
    requested_targets = targets or [
        "opa",
        "cedar",
        "cerbos",
        "agent-hooks",
        "acs",
    ]
    supported = {"opa", "cedar", "cerbos", "agent-hooks", "acs"}
    unknown = sorted(set(requested_targets) - supported)
    if unknown:
        raise ValueError(f"unsupported evaluation targets: {', '.join(unknown)}")
    compile_targets = list(requested_targets)
    if "agent-hooks" in requested_targets and "opa" not in compile_targets:
        compile_targets.append("opa")
    compilations = service.compile_draft(
        project.name,
        policy,
        compile_targets,
    )
    compatibility = {item.target: item.compatible for item in compilations}
    if not all(compatibility.values()):
        raise ValueError("one or more target adapters rejected the policy")

    (destination / "discovery-report.json").write_text(
        discovery.model_dump_json(indent=2),
        encoding="utf-8",
    )
    (destination / "project.yaml").write_text(
        dump_yaml(project),
        encoding="utf-8",
    )
    (destination / "proposed-policy.yaml").write_text(
        dump_yaml(policy),
        encoding="utf-8",
    )
    (destination / "functional-gates.yaml").write_text(
        dump_yaml(
            {
                "gates": [
                    item.model_dump(mode="json") for item in proposal.functional_gates
                ]
            }
        ),
        encoding="utf-8",
    )

    scenarios = build_scenarios(
        project,
        proposal.target_tool,
        policy,
    )
    _write_json(
        destination / "scenarios.json",
        [item.model_dump(mode="json") for item in scenarios],
    )
    if generate_only:
        report = CrossEngineReport(
            project=project.name,
            target_tool=proposal.target_tool,
            policy=policy,
            functional_gates=proposal.functional_gates,
            scenarios=scenarios,
            requested_targets=requested_targets,
            compilation={target: compatibility[target] for target in requested_targets},
            results=[],
            evaluation_performed=False,
            compilation_status=(
                "passed"
                if all(compatibility[target] for target in requested_targets)
                else "failed"
            ),
            evaluation_status="not_run",
            overall_status=(
                "partial"
                if scenarios
                and all(compatibility[target] for target in requested_targets)
                else "failed"
            ),
            all_passed=False,
        )
        (destination / "evaluation-report.json").write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        (destination / "evaluation-report.md").write_text(
            _markdown(report),
            encoding="utf-8",
        )
        _write_evaluation_evidence(destination, report, source)
        return report

    artifact_base = (
        destination
        / "artifacts"
        / "drafts"
        / project.name
        / policy.metadata.name
        / str(policy.metadata.version)
    )
    needs_opa = any(
        target in requested_targets for target in ("opa", "agent-hooks", "acs")
    )
    needs_cedar = "cedar" in requested_targets
    needs_cerbos = "cerbos" in requested_targets
    opa = shutil.which("opa")
    cedar = shutil.which("cedar")
    if needs_opa and opa is None:
        raise RuntimeError("OPA executable was not found")
    if needs_cedar and cedar is None:
        raise RuntimeError("Cedar executable was not found")
    package = policy.metadata.name.replace("-", "_")
    opa_policy = artifact_base / "opa" / "policy" / f"{package}.rego"
    acs_policy = artifact_base / "acs" / "acs" / "policy" / f"{package}.rego"
    cedar_policy = artifact_base / "cedar" / "policy" / f"{policy.metadata.name}.cedar"
    cedar_schema = artifact_base / "cedar" / "policy" / "schema.json"
    cerbos_policies = artifact_base / "cerbos" / "policies"

    results: list[EngineCaseResult] = []
    with TemporaryDirectory(prefix="policy-author-eval-") as temp:
        work = Path(temp)
        cerbos_context = (
            _cerbos_server(
                cerbos_policies,
                work,
                image=cerbos_image,
                port=cerbos_port,
            )
            if needs_cerbos
            else _no_cerbos()
        )
        with cerbos_context as cerbos_url:
            for scenario in scenarios:
                schema_gate = validate_project_action_input(
                    project,
                    proposal.target_tool,
                    scenario.context,
                )
                result_targets = ["canonical"]
                result_targets.extend(
                    {
                        "opa": "opa",
                        "cedar": "cedar",
                        "cerbos": "cerbos",
                        "agent-hooks": "agent-hooks+opa",
                        "acs": "acs+opa",
                    }[target]
                    for target in requested_targets
                )
                if not schema_gate.passed:
                    results.extend(
                        _schema_gate_result(
                            scenario,
                            target,
                            schema_gate.gate_id,
                            schema_gate.detail,
                        )
                        for target in result_targets
                    )
                    continue

                canonical = evaluate_effective_policy(
                    project,
                    proposal.target_tool,
                    policy,
                    scenario.context,
                )
                results.append(
                    _result(
                        scenario,
                        "canonical",
                        NativeDecision(
                            decision=_native_policy_decision(canonical.decision),
                            matched_rule_ids=canonical.matched_rule_ids,
                            detail=canonical.reason,
                        ),
                    )
                )
                opa_decision = (
                    _opa_decision(
                        opa or "opa",
                        opa_policy,
                        f"data.policy_authoring.{package}.decision",
                        scenario.context,
                        work,
                    )
                    if needs_opa
                    else None
                )
                if "opa" in requested_targets and opa_decision is not None:
                    results.append(_result(scenario, "opa", opa_decision))
                if "cedar" in requested_targets:
                    assert cedar is not None
                    results.append(
                        _result(
                            scenario,
                            "cedar",
                            _cedar_decision(
                                cedar,
                                cedar_policy,
                                cedar_schema,
                                scenario.context,
                                proposal.target_tool,
                                work,
                            ),
                        )
                    )
                if "cerbos" in requested_targets:
                    assert cerbos_url is not None
                    results.append(
                        _result(
                            scenario,
                            "cerbos",
                            _cerbos_decision(
                                cerbos_url,
                                scenario.context,
                                proposal.target_tool,
                                policy.metadata.version,
                                scenario.id,
                            ),
                        )
                    )
                if "agent-hooks" in requested_targets and opa_decision is not None:
                    results.append(_result(scenario, "agent-hooks+opa", opa_decision))
                if "acs" in requested_targets:
                    results.append(
                        _result(
                            scenario,
                            "acs+opa",
                            _opa_decision(
                                opa or "opa",
                                acs_policy,
                                f"data.policy_authoring.{package}.decision",
                                _acs_context(scenario.context),
                                work,
                            ),
                        )
                    )

    report = CrossEngineReport(
        project=project.name,
        target_tool=proposal.target_tool,
        policy=policy,
        functional_gates=proposal.functional_gates,
        scenarios=scenarios,
        requested_targets=requested_targets,
        compilation={target: compatibility[target] for target in requested_targets},
        results=results,
        evaluation_performed=True,
        compilation_status=(
            "passed"
            if all(compatibility[target] for target in requested_targets)
            else "failed"
        ),
        evaluation_status=(
            "passed" if results and all(item.passed for item in results) else "failed"
        ),
        overall_status=(
            "passed"
            if results and scenarios and all(item.passed for item in results)
            else "failed"
        ),
        all_passed=bool(results and scenarios and all(item.passed for item in results)),
    )
    (destination / "evaluation-report.json").write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    (destination / "evaluation-report.md").write_text(
        _markdown(report),
        encoding="utf-8",
    )
    _write_evaluation_evidence(destination, report, source)
    return report
