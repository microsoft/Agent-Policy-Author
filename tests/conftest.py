# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from pathlib import Path

import pytest

from policy_authoring.domain.models import ProjectDefinition
from policy_authoring.ingestion.loader import load_project


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).parents[1]


@pytest.fixture
def example_project(project_root: Path) -> ProjectDefinition:
    return load_project(project_root / "examples" / "document-update" / "project.yaml")
