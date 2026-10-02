# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from policy_authoring.domain.input_validation import validate_action_input
from policy_authoring.workspace import verify_publication_bundle


def evaluate_current_opa(
    workspace: Path,
    tool: str,
    context: dict[str, Any],
    *,
    timeout: float = 10,
) -> dict[str, Any]:
    try:
        root = workspace.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(
            "policy workspace could not be resolved; decision is deny"
        ) from exc
    current_path = root / "generated" / "current.json"
    if not current_path.is_file():
        raise RuntimeError("workspace has no current publication bundle")
    try:
        current = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "current publication pointer is invalid; decision is deny"
        ) from exc
    bundle_value = current.get("bundle")
    if not isinstance(bundle_value, str):
        raise RuntimeError("current publication pointer is invalid; decision is deny")
    try:
        bundle = (root / "generated" / bundle_value).resolve(strict=True)
        verify_publication_bundle(bundle)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "current publication bundle verification failed; decision is deny"
        ) from exc
    contract_path = bundle / tool / "opa" / "integration-contract.json"
    if not contract_path.is_file():
        raise RuntimeError(f"current bundle has no OPA contract for {tool}")
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "OPA integration contract is invalid; decision is deny"
        ) from exc
    entrypoint = contract.get("entrypoint")
    if not isinstance(entrypoint, dict):
        raise RuntimeError("OPA integration contract is invalid")
    artifact = entrypoint.get("artifact")
    query = entrypoint.get("query")
    if not isinstance(artifact, str) or not isinstance(query, str):
        raise RuntimeError("OPA integration contract lacks an entrypoint")
    input_contract = contract.get("input")
    if not isinstance(input_contract, dict):
        raise RuntimeError("OPA integration contract lacks an input contract")
    schema = input_contract.get("tool_arguments_schema")
    if not isinstance(schema, dict):
        raise RuntimeError("OPA integration contract lacks a tool argument schema")
    try:
        gate = validate_action_input(schema, tool, context)
    except ValueError as exc:
        raise RuntimeError(
            "OPA integration contract contains an invalid tool schema; "
            "decision is deny"
        ) from exc
    if not gate.passed:
        raise RuntimeError(
            f"action arguments violate the reviewed tool schema; "
            f"decision is deny: {gate.detail}"
        )
    executable = shutil.which("opa")
    if executable is None:
        raise RuntimeError("OPA executable was not found; decision is deny")
    with TemporaryDirectory(prefix="policy-author-runtime-") as temporary:
        input_path = Path(temporary) / "input.json"
        input_path.write_text(json.dumps(context), encoding="utf-8")
        try:
            completed = subprocess.run(
                [
                    executable,
                    "eval",
                    "--format=json",
                    "--data",
                    str(bundle / tool / "opa" / artifact),
                    "--input",
                    str(input_path),
                    query,
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("OPA evaluation timed out; decision is deny") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"OPA evaluation failed; decision is deny: {detail}")
    try:
        value = json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "OPA returned an invalid decision; decision is deny"
        ) from exc
    if not isinstance(value, dict) or value.get("decision") not in {
        "allow",
        "deny",
        "warn",
        "escalate",
    }:
        raise RuntimeError("OPA returned an invalid decision; decision is deny")
    return value
