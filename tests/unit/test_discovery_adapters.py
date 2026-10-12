# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from policy_authoring.discovery import (
    DiscoveryAdapterRegistry,
    DiscoveryLimits,
    default_discovery_registry,
    discover_project,
)
from policy_authoring.discovery.adapters.python import PythonDiscoveryAdapter


def test_default_registry_exposes_language_and_format_suffixes() -> None:
    registry = default_discovery_registry()

    assert {".py", ".ts", ".tsx", ".js", ".json", ".jsonl", ".yaml"} <= (
        registry.supported_suffixes
    )
    assert len({adapter.id for adapter in registry.adapters}) == len(
        registry.adapters
    )


def test_adapter_registry_honors_shared_file_limits(tmp_path: Path) -> None:
    for index in range(2):
        (tmp_path / f"tool_{index}.py").write_text(
            "@tool\ndef get_value(value: str):\n    pass\n",
            encoding="utf-8",
        )
    registry = DiscoveryAdapterRegistry([PythonDiscoveryAdapter()])

    with pytest.raises(ValueError, match="exceeded 1 files"):
        discover_project(
            tmp_path,
            allowed_roots=(tmp_path,),
            limits=DiscoveryLimits(max_files=1),
            registry=registry,
        )


def test_typescript_decorator_discovers_async_method_schema(
    tmp_path: Path,
) -> None:
    (tmp_path / "incident-tools.ts").write_text(
        "class IncidentTools {\n"
        "  /** Close an incident. */\n"
        "  @kernelFunction()\n"
        "  async closeIncident(\n"
        "    incidentId: string,\n"
        "    resolution: 'fixed' | 'mitigated',\n"
        "    notify?: boolean,\n"
        "    retryCount = 3,\n"
        "  ): Promise<void> {}\n"
        "}\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    tool = report.project.tools[0]

    assert tool.name == "closeIncident"
    assert tool.handler == "IncidentTools.closeIncident"
    assert tool.identity is not None
    assert tool.identity.language == "typescript"
    assert tool.identity.framework == "kernelFunction"
    assert tool.source_span is not None
    assert tool.input_schema["properties"] == {
        "incidentId": {"type": "string"},
        "resolution": {
            "type": "string",
            "enum": ["fixed", "mitigated"],
        },
        "notify": {"type": "boolean"},
        "retryCount": {"type": "integer"},
    }
    assert tool.input_schema["required"] == ["incidentId", "resolution"]


def test_typescript_factory_registration_uses_explicit_metadata(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.ts").write_text(
        "export const sendMessage = tool({\n"
        '  name: "send_message",\n'
        '  description: "Send a message.",\n'
        "  inputSchema: {\n"
        '    "type": "object",\n'
        '    "properties": {"recipient": {"type": "string"}},\n'
        '    "required": ["recipient"]\n'
        "  },\n"
        "  mutatesState: true,\n"
        "  requiresApproval: true,\n"
        "  execute: sendMessageHandler\n"
        "});\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    tool = report.project.tools[0]

    assert tool.name == "send_message"
    assert tool.handler == "sendMessageHandler"
    assert tool.risk == "consequential-write"
    assert tool.mutates_state is True
    assert tool.requires_approval is True
    assert tool.input_schema["required"] == ["recipient"]


def test_invalid_typescript_is_reported_without_execution(tmp_path: Path) -> None:
    (tmp_path / "broken.ts").write_text(
        "@tool()\nasync function broken(value: string {\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert any("syntax errors" in warning for warning in report.warnings)


def test_duplicate_canonical_identity_merges_deterministically(
    tmp_path: Path,
) -> None:
    common = {
        "schemaVersion": "1.0",
        "tools": [
            {
                "id": "messaging.send",
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
            }
        ],
    }
    (tmp_path / "a-tools.json").write_text(
        json.dumps(common),
        encoding="utf-8",
    )
    authoritative = json.loads(json.dumps(common))
    authoritative["tools"][0].update(
        {
            "mutatesState": True,
            "requiresApproval": True,
            "language": "typescript",
            "handler": "sendMessage",
        }
    )
    (tmp_path / "b-tools.json").write_text(
        json.dumps(authoritative),
        encoding="utf-8",
    )

    first = discover_project(tmp_path, allowed_roots=(tmp_path,))
    second = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert len(first.project.tools) == 1
    tool = first.project.tools[0]
    assert tool.identity is not None
    assert tool.identity.canonical_id == "messaging.send"
    assert tool.risk == "consequential-write"
    assert tool.provenance is not None
    assert len(tool.provenance) == 2


def test_distinct_identities_with_same_name_are_not_silently_merged(
    tmp_path: Path,
) -> None:
    for index, tool_id in enumerate(("alpha.read", "beta.read")):
        (tmp_path / f"tools-{index}.json").write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "tools": [
                        {
                            "id": tool_id,
                            "name": "read_record",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))

    assert len(report.project.tools) == 2
    assert all(tool.name.startswith("read_record--") for tool in report.project.tools)
    assert any("distinct tool identities" in warning for warning in report.warnings)


def test_evidence_has_adapter_and_source_span(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "@tool\ndef get_status(value: str):\n    pass\n",
        encoding="utf-8",
    )

    report = discover_project(tmp_path, allowed_roots=(tmp_path,))
    evidence = next(item for item in report.evidence if item.kind == "source")

    assert evidence.adapter_id == "python"
    assert evidence.span is not None
    assert evidence.span.path == "agent.py"
    assert evidence.span.start_line == 2


def test_published_inventory_schema_validates_supported_manifest(
    project_root: Path,
) -> None:
    schema_path = project_root / "schemas" / "tool-inventory.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    manifest = {
        "schemaVersion": "1.0",
        "generator": {"name": "test-analyzer", "version": "1.0"},
        "tools": [
            {
                "id": "incident.close",
                "name": "close_incident",
                "language": "typescript",
                "framework": "semantic-kernel",
                "handler": "IncidentTools.closeIncident",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "incidentId": {"type": "string"},
                    },
                    "required": ["incidentId"],
                },
                "mutatesState": True,
                "requiresApproval": True,
                "source": {
                    "path": "src/incident-tools.ts",
                    "startLine": 10,
                    "endLine": 18,
                },
            }
        ],
    }

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)
