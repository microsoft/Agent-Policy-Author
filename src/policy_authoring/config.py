# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    artifact_dir: Path
    discovery_roots: tuple[Path, ...] = ()

    @classmethod
    def from_environment(cls) -> Settings:
        data_dir = Path(os.getenv("POLICY_AUTHOR_DATA_DIR", ".data")).resolve()
        artifact_dir = Path(
            os.getenv("POLICY_AUTHOR_ARTIFACT_DIR", ".artifacts")
        ).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        configured_roots = os.getenv("POLICY_AUTHOR_DISCOVERY_ROOTS")
        roots = (
            tuple(
                Path(item).resolve()
                for item in configured_roots.split(os.pathsep)
                if item.strip()
            )
            if configured_roots
            else (Path.cwd().resolve(),)
        )
        return cls(
            data_dir=data_dir,
            artifact_dir=artifact_dir,
            discovery_roots=roots,
        )
