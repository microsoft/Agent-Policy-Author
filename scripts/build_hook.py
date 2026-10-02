# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"
    _created_build_info = False

    def initialize(
        self,
        version: str,
        build_data: dict[str, Any],
    ) -> None:
        del version, build_data
        target = Path(self.root) / "src" / "policy_authoring" / "_build_info.py"
        if target.exists():
            return
        commit = os.environ.get("POLICY_AUTHOR_BUILD_COMMIT")
        dirty = os.environ.get("POLICY_AUTHOR_BUILD_DIRTY")
        if not commit:
            completed = subprocess.run(
                ["git", "-C", self.root, "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            commit = (
                completed.stdout.strip() if completed.returncode == 0 else "unknown"
            )
        if dirty is None:
            completed = subprocess.run(
                ["git", "-C", self.root, "status", "--porcelain"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            dirty = str(bool(completed.stdout.strip())).lower()
        target.write_text(
            f"SOURCE_COMMIT = {commit!r}\nSOURCE_DIRTY = {dirty!r}\n",
            encoding="utf-8",
        )
        self._created_build_info = True

    def finalize(
        self,
        version: str,
        build_data: dict[str, Any],
        artifact_path: str,
    ) -> None:
        del version, build_data, artifact_path
        target = Path(self.root) / "src" / "policy_authoring" / "_build_info.py"
        if self._created_build_info and target.exists():
            target.unlink()
