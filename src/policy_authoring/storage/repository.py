# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from policy_authoring.domain.models import CanonicalPolicy, ProjectDefinition


class Repository:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    name TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS policies (
                    project_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (project_name, name, version),
                    FOREIGN KEY (project_name) REFERENCES projects(name)
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_name TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    rule_id TEXT,
                    label TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            primary_key = [
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(policies)").fetchall()
                if int(row["pk"]) > 0
            ]
            if primary_key == ["name", "version"]:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE policies RENAME TO policies_legacy;
                    CREATE TABLE policies (
                        project_name TEXT NOT NULL,
                        name TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (project_name, name, version),
                        FOREIGN KEY (project_name) REFERENCES projects(name)
                    );
                    INSERT INTO policies(
                        project_name, name, version, payload, created_at
                    )
                    SELECT project_name, name, version, payload, created_at
                    FROM policies_legacy;
                    DROP TABLE policies_legacy;
                    COMMIT;
                    """
                )

    def save_project(self, project: ProjectDefinition) -> None:
        payload = project.model_dump_json()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO projects(name, payload)
                VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (project.name, payload),
            )

    def get_project(self, name: str) -> ProjectDefinition:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM projects WHERE name = ?",
                (name,),
            ).fetchone()
        if row is None:
            raise KeyError(f"project {name!r} was not found")
        return ProjectDefinition.model_validate_json(row["payload"])

    def list_projects(self) -> list[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT name FROM projects ORDER BY name"
            ).fetchall()
        return [str(row["name"]) for row in rows]

    def save_policy(self, project_name: str, policy: CanonicalPolicy) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO policies(
                    project_name, name, version, payload
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    project_name,
                    policy.metadata.name,
                    policy.metadata.version,
                    policy.model_dump_json(),
                ),
            )

    def get_policy(
        self,
        project_name: str,
        name: str,
        version: int | None = None,
    ) -> CanonicalPolicy:
        query = "SELECT payload FROM policies WHERE project_name = ? AND name = ?"
        parameters: tuple[Any, ...] = (project_name, name)
        if version is not None:
            query += " AND version = ?"
            parameters = (project_name, name, version)
        query += " ORDER BY version DESC LIMIT 1"
        with self._connection() as connection:
            row = connection.execute(query, parameters).fetchone()
        if row is None:
            raise KeyError(f"policy {name!r} was not found in project {project_name!r}")
        return CanonicalPolicy.model_validate_json(row["payload"])

    def save_feedback(
        self,
        project_name: str,
        policy_name: str,
        label: str,
        detail: str,
        rule_id: str | None = None,
    ) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO feedback(
                    project_name, policy_name, rule_id, label, detail
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (project_name, policy_name, rule_id, label, detail),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("feedback insert did not return an identifier")
            return cursor.lastrowid

    def list_feedback(
        self,
        project_name: str,
        policy_name: str,
    ) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, rule_id, label, detail, created_at
                FROM feedback
                WHERE project_name = ? AND policy_name = ?
                ORDER BY id
                """,
                (project_name, policy_name),
            ).fetchall()
        return [dict(row) for row in rows]

    def export_json(self) -> dict[str, Any]:
        return {
            "projects": self.list_projects(),
            "database": str(self.path),
        }
