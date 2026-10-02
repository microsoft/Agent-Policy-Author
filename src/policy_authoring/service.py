# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from policy_authoring.adapters.registry import default_registry
from policy_authoring.discovery import DiscoveryLimits, discover_project
from policy_authoring.domain.evaluator import evaluate_policy
from policy_authoring.domain.models import (
    CanonicalPolicy,
    CompilationResult,
    DiscoveryReport,
    PolicyTestCase,
    ProjectDefinition,
    Recommendation,
)
from policy_authoring.domain.validation import (
    require_unique_test_ids,
    require_valid_policy,
)
from policy_authoring.recommendation.service import (
    recommend_policies,
    synthesize_policy,
)
from policy_authoring.storage.repository import Repository
from policy_authoring.testing.generator import generate_tests


class AuthoringService:
    def __init__(self, repository: Repository, artifact_root: Path) -> None:
        self.repository = repository
        self.artifact_root = artifact_root.resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.adapters = default_registry()

    def import_project(self, project: ProjectDefinition) -> ProjectDefinition:
        self.repository.save_project(project)
        return project

    def discover(
        self,
        path: Path,
        *,
        allowed_roots: tuple[Path, ...] = (),
        limits: DiscoveryLimits | None = None,
        import_project: bool = True,
    ) -> DiscoveryReport:
        report = discover_project(
            path,
            allowed_roots=allowed_roots,
            limits=limits,
        )
        if import_project:
            self.repository.save_project(report.project)
        return report

    def recommendations(
        self,
        project_name: str,
        tool_name: str | None = None,
    ) -> list[Recommendation]:
        project = self.repository.get_project(project_name)
        return recommend_policies(project, tool_name)

    def synthesize(
        self,
        project_name: str,
        tool_name: str,
    ) -> CanonicalPolicy:
        project = self.repository.get_project(project_name)
        policy = synthesize_policy(project, tool_name)
        require_valid_policy(policy, project)
        self.repository.save_policy(project_name, policy)
        return policy

    def test_policy(
        self,
        policy: CanonicalPolicy,
        base_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        cases = generate_tests(policy, base_context)
        return self.run_cases(policy, cases)

    @staticmethod
    def run_cases(
        policy: CanonicalPolicy,
        cases: list[PolicyTestCase],
    ) -> list[dict[str, Any]]:
        require_unique_test_ids(cases)
        results = []
        for case in cases:
            decision = evaluate_policy(policy, case.context)
            results.append(
                {
                    "id": case.id,
                    "description": case.description,
                    "expected": case.expected_decision,
                    "actual": decision.decision,
                    "passed": decision.decision == case.expected_decision,
                    "matched_rule_ids": decision.matched_rule_ids,
                    "reason": decision.reason,
                }
            )
        return results

    def compile_draft(
        self,
        project_name: str,
        policy: CanonicalPolicy,
        targets: list[str],
    ) -> list[CompilationResult]:
        project = self.repository.get_project(project_name)
        require_valid_policy(policy, project)
        ordered_targets = self.adapters.order_selection(targets)
        results = [
            self.adapters.get(target).compile(policy, project)
            for target in ordered_targets
        ]
        for result in results:
            if result.compatible:
                self._write_draft_artifacts(project_name, policy, result)
        return results

    def _write_draft_artifacts(
        self,
        project_name: str,
        policy: CanonicalPolicy,
        result: CompilationResult,
    ) -> None:
        base = (
            self.artifact_root
            / "drafts"
            / project_name
            / policy.metadata.name
            / str(policy.metadata.version)
            / result.target
        ).resolve()
        if not base.is_relative_to(self.artifact_root):
            raise ValueError("artifact path escapes configured root")
        if base.exists():
            shutil.rmtree(base)
        base.mkdir(parents=True, exist_ok=True)
        for artifact in result.artifacts:
            destination = (base / artifact.path).resolve()
            if not destination.is_relative_to(base):
                raise ValueError("generated artifact path escapes target root")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(artifact.content, encoding="utf-8")
        manifest = {
            "authority": "draft",
            "approved": False,
            "review_status": policy.metadata.review_status,
            "project": project_name,
            "policy": policy.metadata.name,
            "version": policy.metadata.version,
            "target": result.target,
            "canonical_digest": hashlib.sha256(
                policy.model_dump_json().encode("utf-8")
            ).hexdigest(),
            "artifacts": [
                {
                    "path": artifact.path,
                    "media_type": artifact.media_type,
                    "sha256": hashlib.sha256(
                        artifact.content.encode("utf-8")
                    ).hexdigest(),
                }
                for artifact in result.artifacts
            ],
        }
        (base / "draft-manifest.json").write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )

    def tuning_suggestions(
        self,
        project_name: str,
        policy_name: str,
    ) -> list[dict[str, Any]]:
        feedback = self.repository.list_feedback(project_name, policy_name)
        grouped: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
        for item in feedback:
            key = (item["rule_id"], item["label"])
            grouped.setdefault(key, []).append(item)

        suggestions = []
        for (rule_id, label), items in sorted(
            grouped.items(),
            key=lambda entry: (
                str(entry[0][0]),
                entry[0][1],
            ),
        ):
            if label == "false_positive":
                action = "Review or narrow the rule condition"
            elif label == "false_negative":
                action = "Add or strengthen a blocking condition"
            else:
                action = "Review the collected policy feedback"
            suggestions.append(
                {
                    "rule_id": rule_id,
                    "label": label,
                    "count": len(items),
                    "recommendation": action,
                    "evidence": [item["detail"] for item in items],
                    "automatic_change": False,
                }
            )
        return suggestions
