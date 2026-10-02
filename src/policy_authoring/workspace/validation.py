# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

import yaml

from policy_authoring.adapters.registry import default_registry


class TargetValidation(TypedDict):
    status: Literal["validated", "validation_not_run", "failed"]
    detail: str
    assurance: NotRequired[str]
    validator: NotRequired[dict[str, Any]]


def _run(
    command: list[str],
    *,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8") if isinstance(exc.stdout, bytes) else exc.stdout
        )
        return subprocess.CompletedProcess(
            command,
            returncode=124,
            stdout=stdout or "",
            stderr=f"validation timed out after {timeout:g}s",
        )


def _failure(
    name: str,
    completed: subprocess.CompletedProcess[str],
) -> TargetValidation:
    detail = completed.stderr.strip() or completed.stdout.strip()
    return {
        "status": "failed",
        "detail": f"{name} validation failed: {detail or 'unknown error'}",
    }


def _validate_json_and_yaml(root: Path) -> TargetValidation | None:
    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() == ".json":
                json.loads(path.read_text(encoding="utf-8"))
            elif path.suffix.lower() in {".yaml", ".yml"}:
                yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        return {"status": "failed", "detail": f"structured artifact error: {exc}"}
    return None


def _validate_rego(root: Path) -> TargetValidation:
    rego_files = sorted(root.rglob("*.rego"))
    if not rego_files:
        return {"status": "failed", "detail": "no Rego policy was generated"}
    executable = shutil.which("opa")
    if executable is None:
        return {
            "status": "validation_not_run",
            "detail": "OPA executable was not found; artifacts were rendered only",
        }
    completed = _run([executable, "check", *map(str, rego_files)])
    if completed.returncode != 0:
        return _failure("OPA", completed)
    return {
        "status": "validated",
        "detail": f"OPA accepted {len(rego_files)} Rego artifact(s)",
    }


def _validate_cedar(root: Path) -> TargetValidation:
    policy_files = sorted(root.rglob("*.cedar"))
    schema_files = sorted(path for path in root.rglob("schema.json") if path.is_file())
    if len(policy_files) != 1 or len(schema_files) != 1:
        return {
            "status": "failed",
            "detail": "Cedar output must contain one policy and one schema",
        }
    executable = shutil.which("cedar")
    if executable is None:
        return {
            "status": "validation_not_run",
            "detail": "Cedar executable was not found; artifacts were rendered only",
        }
    parsed = _run(
        [
            executable,
            "check-parse",
            "--policies",
            str(policy_files[0]),
            "--error-format",
            "plain",
        ]
    )
    if parsed.returncode != 0:
        return _failure("Cedar parse", parsed)
    validated = _run(
        [
            executable,
            "validate",
            "--schema",
            str(schema_files[0]),
            "--schema-format",
            "json",
            "--policies",
            str(policy_files[0]),
            "--error-format",
            "plain",
        ]
    )
    if validated.returncode != 0:
        return _failure("Cedar schema", validated)
    return {
        "status": "validated",
        "detail": "Cedar accepted the policy and schema",
    }


def _validate_agent_hooks(root: Path) -> TargetValidation:
    bindings = sorted(root.rglob("binding.json"))
    if len(bindings) != 1:
        return {
            "status": "failed",
            "detail": "Agent Hooks output must contain one binding.json",
        }
    binding = json.loads(bindings[0].read_text(encoding="utf-8"))
    evaluator = binding.get("spec", {}).get("evaluator")
    if not isinstance(evaluator, dict):
        return {
            "status": "failed",
            "detail": "Agent Hooks binding is missing its evaluator contract",
        }
    required = {
        "target",
        "artifact",
        "query",
        "requestSchema",
        "responseSchema",
        "failureMode",
    }
    if not required.issubset(evaluator):
        return {
            "status": "failed",
            "detail": "Agent Hooks evaluator contract is incomplete",
        }
    if evaluator.get("target") != "opa" or evaluator.get("failureMode") != "deny":
        return {
            "status": "failed",
            "detail": "Agent Hooks evaluator must target OPA and fail closed",
        }
    for key in ("artifact", "requestSchema", "responseSchema"):
        reference = evaluator.get(key)
        if not isinstance(reference, str):
            return {
                "status": "failed",
                "detail": f"Agent Hooks evaluator {key} reference is invalid",
            }
        referenced_path = (bindings[0].parent / reference).resolve()
        tool_root = root.parent.resolve()
        if not referenced_path.is_relative_to(tool_root):
            return {
                "status": "failed",
                "detail": (
                    f"Agent Hooks evaluator {key} resolves outside the "
                    "published tool package"
                ),
            }
        if not referenced_path.is_file():
            return {
                "status": "failed",
                "detail": (
                    f"Agent Hooks evaluator {key} does not resolve to an "
                    "existing artifact"
                ),
            }
    return {
        "status": "validated",
        "detail": "Agent Hooks binding and evaluator references are complete",
    }


def _validate_acs_contract(root: Path) -> TargetValidation | None:
    manifests = sorted(root.rglob("manifest.yaml"))
    if len(manifests) != 1:
        return {
            "status": "failed",
            "detail": "AGT ACS output must contain one manifest.yaml",
        }
    manifest_path = manifests[0]
    document = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return {
            "status": "failed",
            "detail": "AGT ACS manifest must be a mapping",
        }
    version = document.get("agent_control_specification_version")
    if version != "0.4.0-alpha.1":
        return {
            "status": "failed",
            "detail": (
                "AGT ACS manifest must target version 0.4.0-alpha.1; "
                f"found {version!r}"
            ),
        }
    policies = document.get("policies")
    points = document.get("intervention_points")
    tools = document.get("tools")
    if not isinstance(policies, dict) or not policies:
        return {
            "status": "failed",
            "detail": "AGT ACS manifest must declare at least one policy",
        }
    if not isinstance(points, dict) or not points:
        return {
            "status": "failed",
            "detail": "AGT ACS manifest must declare an intervention point",
        }
    if not isinstance(tools, dict) or not tools:
        return {
            "status": "failed",
            "detail": "AGT ACS manifest must declare its governed tools",
        }
    root_resolved = root.resolve()
    for policy_id, policy in policies.items():
        if (
            not isinstance(policy_id, str)
            or not policy_id
            or not isinstance(policy, dict)
            or policy.get("type") != "rego"
        ):
            return {
                "status": "failed",
                "detail": "AGT ACS policies must be named Rego policy definitions",
            }
        bundle = policy.get("bundle")
        query = policy.get("query")
        if not isinstance(bundle, str) or not bundle:
            return {
                "status": "failed",
                "detail": f"AGT ACS policy {policy_id!r} is missing its bundle",
            }
        if not isinstance(query, str) or not query:
            return {
                "status": "failed",
                "detail": f"AGT ACS policy {policy_id!r} is missing its query",
            }
        bundle_path = (manifest_path.parent / bundle).resolve()
        if not bundle_path.is_relative_to(root_resolved):
            return {
                "status": "failed",
                "detail": f"AGT ACS policy {policy_id!r} bundle escapes its package",
            }
        if not bundle_path.is_dir() or not any(bundle_path.rglob("*.rego")):
            return {
                "status": "failed",
                "detail": (
                    f"AGT ACS policy {policy_id!r} bundle contains no Rego policy"
                ),
            }
    allowed_points = {
        "agent_startup",
        "input",
        "pre_model_call",
        "post_model_call",
        "pre_tool_call",
        "post_tool_call",
        "output",
        "agent_shutdown",
    }
    for point_name, point in points.items():
        if point_name not in allowed_points or not isinstance(point, dict):
            return {
                "status": "failed",
                "detail": f"AGT ACS intervention point {point_name!r} is invalid",
            }
        target = point.get("policy_target")
        binding = point.get("policy")
        if not isinstance(target, str) or not target.startswith("$."):
            return {
                "status": "failed",
                "detail": (
                    f"AGT ACS intervention point {point_name!r} has an invalid "
                    "policy_target"
                ),
            }
        if (
            not isinstance(binding, dict)
            or not isinstance(binding.get("id"), str)
            or binding["id"] not in policies
        ):
            return {
                "status": "failed",
                "detail": (
                    f"AGT ACS intervention point {point_name!r} references an "
                    "unknown policy"
                ),
            }
        tool_name_from = point.get("tool_name_from")
        if point_name in {"pre_tool_call", "post_tool_call"} and (
            not isinstance(tool_name_from, str)
            or not tool_name_from.startswith("$.")
        ):
            return {
                "status": "failed",
                "detail": (
                    f"AGT ACS intervention point {point_name!r} must project "
                    "the tool name"
                ),
            }
    return None


def _validate_acs(root: Path) -> TargetValidation:
    contract_error = _validate_acs_contract(root)
    if contract_error is not None:
        return contract_error
    rego = _validate_rego(root)
    rego["detail"] = "AGT ACS 0.4.0-alpha.1 contract accepted; " + rego["detail"]
    return rego


def _validate_cerbos_contract(root: Path) -> TargetValidation:
    policies = sorted(root.rglob("*.yaml"))
    if len(policies) != 1:
        return {
            "status": "failed",
            "detail": "Cerbos output must contain one resource policy",
        }
    document = yaml.safe_load(policies[0].read_text(encoding="utf-8"))
    resource_policy = (
        document.get("resourcePolicy") if isinstance(document, dict) else None
    )
    if not isinstance(resource_policy, dict):
        return {
            "status": "failed",
            "detail": "Cerbos resourcePolicy is missing",
        }
    rules = resource_policy.get("rules")
    if not isinstance(rules, list) or not rules:
        return {
            "status": "failed",
            "detail": "Cerbos resource policy must contain rules",
        }
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or not isinstance(rule.get("name"), str)
            or rule.get("effect") not in {"EFFECT_ALLOW", "EFFECT_DENY"}
        ):
            return {
                "status": "failed",
                "detail": "Cerbos resource policy contains an invalid rule",
            }
    return {
        "status": "validated",
        "detail": "Cerbos resource policy contract is valid",
    }


def _validator_version(executable: str | None) -> str | None:
    if executable is None:
        return None
    completed = _run([executable, "--version"], timeout=10)
    if completed.returncode != 0:
        completed = _run([executable, "version"], timeout=10)
    value = completed.stdout.strip() or completed.stderr.strip()
    return value.splitlines()[0] if value else None


def validate_target(target: str, root: Path) -> TargetValidation:
    started_at = datetime.now(UTC)
    structured_error = _validate_json_and_yaml(root)
    if structured_error is not None:
        result = structured_error
    elif target == "opa":
        result = _validate_rego(root)
    elif target == "acs":
        result = _validate_acs(root)
    elif target == "agent-hooks":
        result = _validate_agent_hooks(root)
    elif target == "cedar":
        result = _validate_cedar(root)
    elif target == "cerbos":
        result = _validate_cerbos_contract(root)
    else:
        result = {"status": "failed", "detail": f"unsupported target: {target}"}
    adapter = default_registry().get(target)
    executable = (
        shutil.which("opa")
        if target in {"opa", "acs"}
        else shutil.which("cedar")
        if target == "cedar"
        else None
    )
    result["assurance"] = adapter.capabilities.validation_assurance
    result["validator"] = {
        "name": target,
        "executable": executable,
        "version": _validator_version(executable),
        "platform": platform.platform(),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "timeout_seconds": 30,
        "result_digest": "sha256:"
        + hashlib.sha256(result["detail"].encode("utf-8")).hexdigest(),
    }
    return result
