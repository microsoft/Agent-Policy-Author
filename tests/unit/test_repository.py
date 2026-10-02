# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import sqlite3
from pathlib import Path

from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    ContextContract,
    Operand,
    PolicyMetadata,
    PolicyRule,
    ProjectDefinition,
)
from policy_authoring.storage.repository import Repository


def _project(name: str) -> ProjectDefinition:
    return ProjectDefinition(
        name=name,
        tools=[],
        context=ContextContract(),
    )


def _policy(tool: str) -> CanonicalPolicy:
    return CanonicalPolicy(
        metadata=PolicyMetadata(name="shared-policy"),
        tool=tool,
        rules=[
            PolicyRule(
                id="deny-unknown",
                decision="deny",
                reason="Unknown principals are denied",
                condition=Condition(
                    operator="exists",
                    left=Operand(path="principal.id"),
                ),
            )
        ],
    )


def test_policies_are_isolated_by_project(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "policy-authoring.db")
    repository.save_project(_project("project-one"))
    repository.save_project(_project("project-two"))
    repository.save_policy("project-one", _policy("tool-one"))
    repository.save_policy("project-two", _policy("tool-two"))

    assert repository.get_policy("project-one", "shared-policy").tool == "tool-one"
    assert repository.get_policy("project-two", "shared-policy").tool == "tool-two"


def test_legacy_policy_table_is_migrated(tmp_path: Path) -> None:
    database = tmp_path / "policy-authoring.db"
    project = _project("legacy-project")
    policy = _policy("legacy-tool")
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE projects (
                name TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE policies (
                name TEXT NOT NULL,
                version INTEGER NOT NULL,
                project_name TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (name, version),
                FOREIGN KEY (project_name) REFERENCES projects(name)
            );
            """
        )
        connection.execute(
            "INSERT INTO projects(name, payload) VALUES (?, ?)",
            (project.name, project.model_dump_json()),
        )
        connection.execute(
            """
            INSERT INTO policies(name, version, project_name, payload)
            VALUES (?, ?, ?, ?)
            """,
            (
                policy.metadata.name,
                policy.metadata.version,
                project.name,
                policy.model_dump_json(),
            ),
        )

    repository = Repository(database)

    assert (
        repository.get_policy(
            "legacy-project",
            "shared-policy",
        ).tool
        == "legacy-tool"
    )
    with sqlite3.connect(database) as connection:
        primary_key = [
            row[1]
            for row in connection.execute("PRAGMA table_info(policies)")
            if row[5] > 0
        ]
    assert primary_key == ["project_name", "name", "version"]


def test_repository_closes_database_connections(tmp_path: Path) -> None:
    database = tmp_path / "policy-authoring.db"
    repository = Repository(database)
    repository.save_project(_project("close-check"))
    assert repository.list_projects() == ["close-check"]

    renamed = tmp_path / "renamed.db"
    database.rename(renamed)

    assert renamed.is_file()
