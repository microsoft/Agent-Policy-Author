# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from policy_authoring.domain.models import CanonicalPolicy, ProjectDefinition

MAX_INPUT_BYTES = 2 * 1024 * 1024


def format_validation_error(error: ValidationError) -> str:
    details: list[str] = []
    for item in error.errors(
        include_url=False,
        include_input=False,
    ):
        location = ".".join(str(part) for part in item["loc"])
        message = str(item["msg"]).removeprefix("Value error, ")
        details.append(f"{location}: {message}" if location else message)
    return "; ".join(details)


def _read_document(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        text = resolved.read_text(encoding="utf-8")
        if resolved.suffix.lower() == ".json":
            value = json.loads(text)
        elif resolved.suffix.lower() in {".yaml", ".yml"}:
            value = yaml.safe_load(text)
        else:
            raise ValueError("only JSON and YAML inputs are supported")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{resolved}:{exc.lineno}:{exc.colno}: {exc.msg}") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f":{mark.line + 1}:{mark.column + 1}" if mark is not None else ""
        problem = getattr(exc, "problem", None) or str(exc)
        raise ValueError(f"{resolved}{location}: {problem}") from exc
    if not isinstance(value, dict):
        raise ValueError("input document must be an object")
    return value


def load_project(path: Path) -> ProjectDefinition:
    try:
        return ProjectDefinition.model_validate(_read_document(path))
    except ValidationError as exc:
        raise ValueError(
            f"{path.resolve()}: {format_validation_error(exc)}"
        ) from exc


def load_policy(path: Path) -> CanonicalPolicy:
    try:
        return CanonicalPolicy.model_validate(_read_document(path))
    except ValidationError as exc:
        raise ValueError(
            f"{path.resolve()}: {format_validation_error(exc)}"
        ) from exc


def dump_yaml(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=True)
    return yaml.safe_dump(value, sort_keys=False)
