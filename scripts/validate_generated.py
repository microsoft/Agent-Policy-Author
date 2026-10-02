# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import warnings
from pathlib import Path

import jsonschema
import yaml
from jsonschema import Draft202012Validator


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def validate_schema(value_path: Path, schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if value_path.suffix in {".yaml", ".yml"}:
        value = yaml.safe_load(value_path.read_text(encoding="utf-8"))
    else:
        value = json.loads(value_path.read_text(encoding="utf-8"))
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="jsonschema.RefResolver is deprecated.*",
            category=DeprecationWarning,
        )
        resolver = jsonschema.RefResolver(
            base_uri=schema_path.as_uri(),
            referrer=schema,
        )
        Draft202012Validator(schema, resolver=resolver).validate(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument(
        "--acs-schema-root",
        type=Path,
        help="Directory containing ACS manifest.schema.json and wire schemas.",
    )
    parser.add_argument(
        "--agent-hooks-schema-root",
        type=Path,
        help="Directory containing Agent Hooks schemas.",
    )
    args = parser.parse_args()
    root = args.artifact_root.resolve(strict=True)

    for path in root.rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
    for path in root.rglob("*.yaml"):
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{path} must contain an object")

    opa = shutil.which("opa")
    rego_files = list(root.rglob("*.rego"))
    if opa is None and rego_files:
        raise RuntimeError("OPA is required to validate generated Rego")
    for path in rego_files:
        run([opa or "opa", "check", str(path)])

    cedar = shutil.which("cedar")
    cedar_files = list(root.rglob("*.cedar"))
    if cedar is None and cedar_files:
        raise RuntimeError("Cedar CLI is required to validate generated policies")
    for path in cedar_files:
        schema = path.parent / "schema.json"
        run(
            [
                cedar or "cedar",
                "validate",
                "--policies",
                str(path),
                "--schema",
                str(schema),
                "--schema-format",
                "json",
                "--error-format",
                "plain",
            ]
        )

    cerbos = os.getenv("CERBOS_BIN") or shutil.which("cerbos")
    cerbos_policy_dirs = [
        path for path in root.rglob("policies") if path.parent.name == "cerbos"
    ]
    if cerbos is not None:
        for path in cerbos_policy_dirs:
            run([cerbos, "compile", "--skip-tests", str(path)])
    elif cerbos_policy_dirs:
        print("Cerbos native validation skipped: cerbos binary unavailable")

    if args.acs_schema_root is not None:
        acs_root = args.acs_schema_root.resolve(strict=True)
        validate_schema(
            root / "acs" / "acs" / "manifest.yaml",
            acs_root / "manifest.schema.json",
        )
        validate_schema(
            root / "acs" / "acs" / "policy-input.sample.json",
            acs_root / "wire" / "policy-input.schema.json",
        )

    if args.agent_hooks_schema_root is not None:
        hooks_root = args.agent_hooks_schema_root.resolve(strict=True)
        validate_schema(
            (root / "agent-hooks" / "agent-hooks" / "conformance-context.json"),
            hooks_root / "agent-context" / "pre_tool_call.schema.json",
        )

    print(f"Validated generated artifacts under {root}")


if __name__ == "__main__":
    main()
