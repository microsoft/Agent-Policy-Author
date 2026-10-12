# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Decision = Literal["allow", "deny", "warn", "escalate", "transform"]
RunStatus = Literal[
    "passed",
    "failed",
    "partial",
    "not_run",
    "not_applicable",
    "blocked",
    "needs_review",
]
ControlKind = Literal[
    "schema_validation",
    "operation_binding",
    "version_check",
    "idempotency",
    "approval_binding",
    "mutation_boundary",
    "audit",
    "policy_decision",
    "execution",
]
Operator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "exists",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "all",
    "any",
    "not",
]


def _require_unique(values: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        raise ValueError(f"duplicate {label}: {', '.join(duplicates)}")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Operand(StrictModel):
    path: str | None = None
    literal: Any = None

    @model_validator(mode="after")
    def exactly_one_source(self) -> Operand:
        if (self.path is None) == (self.literal is None):
            raise ValueError("operand requires exactly one of path or literal")
        return self


class Condition(StrictModel):
    operator: Operator
    left: Operand | None = None
    right: Operand | None = None
    values: list[Any] = Field(default_factory=list)
    conditions: list[Condition] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> Condition:
        binary = {
            "equals",
            "not_equals",
            "greater_than",
            "greater_than_or_equal",
            "less_than",
            "less_than_or_equal",
        }
        if self.operator in binary and (self.left is None or self.right is None):
            raise ValueError(f"{self.operator} requires left and right operands")
        if self.operator in {"in", "not_in"} and (self.left is None or not self.values):
            raise ValueError(f"{self.operator} requires a left operand and values")
        if self.operator == "exists" and self.left is None:
            raise ValueError("exists requires a left operand")
        if self.operator in {"all", "any"} and not self.conditions:
            raise ValueError(f"{self.operator} requires child conditions")
        if self.operator == "not" and len(self.conditions) != 1:
            raise ValueError("not requires exactly one child condition")
        return self


class PolicyRule(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    decision: Decision
    reason: str = Field(min_length=1, max_length=160)
    condition: Condition


class PolicyMetadata(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    version: int = Field(default=1, ge=1)
    description: str = ""
    review_status: Literal[
        "needs_review",
        "approved",
        "rejected",
    ] = "needs_review"


class SourceReference(StrictModel):
    path: str
    line: int | None = Field(default=None, ge=1)
    symbol: str | None = None
    role: Literal[
        "tool_registration",
        "tool_handler",
        "enforcement_point",
    ] = "tool_handler"


class CanonicalPolicy(StrictModel):
    api_version: Literal["policyauthor.dev/v1alpha1"] = "policyauthor.dev/v1alpha1"
    kind: Literal["ActionPolicy"] = "ActionPolicy"
    metadata: PolicyMetadata
    tool: str
    tool_schema_version: str = "1"
    interception_point: Literal[
        "agent_startup",
        "input",
        "pre_model_call",
        "post_model_call",
        "pre_tool_call",
        "post_tool_call",
        "output",
        "agent_shutdown",
    ] = "pre_tool_call"
    default_decision: Decision = "deny"
    source_targets: list[SourceReference] = Field(default_factory=list)
    rules: list[PolicyRule]

    @model_validator(mode="after")
    def require_unique_identities(self) -> CanonicalPolicy:
        _require_unique([rule.id for rule in self.rules], "policy rule id")
        return self


class ContextAttribute(StrictModel):
    path: str
    type: Literal["string", "number", "integer", "boolean", "object", "array"]
    trust: Literal[
        "authenticated",
        "resource_resolver",
        "workflow_store",
        "approval_store",
        "runtime_configuration",
        "model_provided",
        "untrusted",
    ]
    source: str | None = None


class ContextContract(StrictModel):
    attributes: list[ContextAttribute] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_paths(self) -> ContextContract:
        _require_unique(
            [attribute.path for attribute in self.attributes],
            "context attribute path",
        )
        return self


class SourceSpan(StrictModel):
    path: str
    start_line: int = Field(ge=1)
    start_column: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)


class ToolIdentity(StrictModel):
    canonical_id: str
    declared_name: str
    language: str | None = None
    framework: str | None = None
    namespace: str | None = None
    qualified_name: str | None = None


class ToolProvenance(StrictModel):
    source_kind: Literal[
        "project",
        "runtime_manifest",
        "manifest",
        "constructor",
        "decorator",
        "openapi",
        "source",
        "heuristic",
    ]
    adapter_id: str
    confidence: float = Field(ge=0, le=1)
    language: str | None = None
    framework: str | None = None
    span: SourceSpan | None = None


class ToolDefinition(StrictModel):
    name: str
    description: str = ""
    risk: Literal["read", "write", "consequential-write", "unknown"] = "unknown"
    schema_version: str = "1"
    input_schema: dict[str, Any]
    mutates_state: bool | None = None
    requires_approval: bool | None = None
    domain: str | None = None
    handler: str | None = None
    source_path: str | None = None
    source_line: int | None = Field(default=None, ge=1)
    source_span: SourceSpan | None = None
    identity: ToolIdentity | None = None
    provenance: list[ToolProvenance] | None = None
    metadata_source: Literal[
        "project",
        "runtime_manifest",
        "manifest",
        "constructor",
        "decorator",
        "openapi",
        "heuristic",
    ] = "heuristic"


class ControlObservation(StrictModel):
    kind: ControlKind
    target_tool: str | None = None
    detail: str
    path: str
    line: int | None = Field(default=None, ge=1)
    confidence: float = Field(ge=0, le=1)


class TraceStep(StrictModel):
    type: Literal["tool_call", "tool_result"]
    tool: str
    arguments: dict[str, Any] | None = None
    output: dict[str, Any] | None = None


class AgentTrace(StrictModel):
    id: str
    outcome: Literal["success", "failure"] = "success"
    steps: list[TraceStep]


class ProjectDefinition(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    description: str = ""
    tools: list[ToolDefinition]
    context: ContextContract
    traces: list[AgentTrace] = Field(default_factory=list)
    controls: list[ControlObservation] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_identities(self) -> ProjectDefinition:
        _require_unique([tool.name for tool in self.tools], "tool name")
        _require_unique([trace.id for trace in self.traces], "trace id")
        return self


class Recommendation(StrictModel):
    id: str
    title: str
    detail: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]
    rule: PolicyRule


class FunctionalGate(StrictModel):
    id: str
    stage: Literal[
        "schema_validation",
        "trusted_context",
        "approval",
        "operation_binding",
        "version_control",
        "idempotency",
        "policy_decision",
        "execution",
    ]
    target_tool: str
    requirement: str
    enforcement: Literal["deny", "escalate"]
    rule_ids: list[str] = Field(default_factory=list)
    trusted_context_paths: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class PolicyProposal(StrictModel):
    target_tool: str
    recommendations: list[Recommendation]
    policy: CanonicalPolicy
    functional_gates: list[FunctionalGate]


class PolicyTestCase(StrictModel):
    id: str
    description: str
    context: dict[str, Any]
    expected_decision: Decision


class DecisionResult(StrictModel):
    decision: Decision
    matched_rule_ids: list[str]
    reason: str


class GeneratedArtifact(StrictModel):
    path: str
    media_type: str
    content: str


class CompatibilityItem(StrictModel):
    rule_id: str
    status: Literal["supported", "lowered", "unsupported"]
    fidelity: Literal["exact", "lossy_fail_closed", "unsupported"] = "exact"
    detail: str

    @model_validator(mode="after")
    def align_fidelity(self) -> CompatibilityItem:
        if self.status == "unsupported":
            self.fidelity = "unsupported"
        elif self.status == "lowered" and self.fidelity == "exact":
            self.fidelity = "lossy_fail_closed"
        return self


class CompilationResult(StrictModel):
    target: str
    compatible: bool
    compatibility: list[CompatibilityItem]
    artifacts: list[GeneratedArtifact]


class DiscoveryEvidence(StrictModel):
    kind: Literal[
        "source",
        "schema",
        "trace",
        "manifest",
        "context",
        "control",
    ]
    path: str
    detail: str
    confidence: float = Field(ge=0, le=1)
    adapter_id: str | None = None
    span: SourceSpan | None = None


class DiscoveryQuestion(StrictModel):
    id: str
    title: str
    detail: str
    subject: str
    options: list[str] = Field(default_factory=list)
    recommended: str | None = None


class DiscoverySummary(StrictModel):
    files_scanned: int
    bytes_scanned: int
    tools_discovered: int
    consequential_tools: int
    mutating_tools: int = 0
    approval_required_tools: int = 0
    traces_imported: int
    context_attributes: int
    controls_observed: int = 0
    unresolved_questions: int


class DiscoveryProvenance(StrictModel):
    mode: Literal["explicit_project", "source_scan"]
    selected_source: str | None = None
    project_definition: str | None = None
    ignored_directories: list[str] = Field(default_factory=list)
    adapters: list[str] | None = None


class DiscoveryReport(StrictModel):
    root: str
    project: ProjectDefinition
    provenance: DiscoveryProvenance
    summary: DiscoverySummary
    evidence: list[DiscoveryEvidence]
    questions: list[DiscoveryQuestion]
    proposals: list[PolicyProposal] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CapabilityInventory(StrictModel):
    project: str
    tools: list[ToolDefinition]
    total_tools: int
    mutating_tools: int
    approval_required_tools: int
    unknown_tools: int
    evidence: list[DiscoveryEvidence] = Field(default_factory=list)


class ControlRequirement(StrictModel):
    id: str
    target_tool: str
    kind: ControlKind
    requirement: str
    implementation_status: Literal[
        "existing",
        "proposed",
        "partial",
        "unknown",
    ]
    enforcement_point: Literal[
        "schema",
        "host_runtime",
        "policy",
        "tool",
    ]
    evidence: list[str] = Field(default_factory=list)
    context_paths: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class PolicyCoverage(StrictModel):
    total_tools: int
    classified_tools: int
    mutating_tools: int
    approval_required_tools: int
    policy_candidates: int
    policies_generated: int
    policies_with_rules: int
    scenarios_generated: int


class ControlAnalysis(StrictModel):
    project: str
    requirements: list[ControlRequirement]
    coverage: PolicyCoverage
    gaps: list[str] = Field(default_factory=list)
    review_questions: list[DiscoveryQuestion] = Field(default_factory=list)


class PhaseOutcome(StrictModel):
    phase: Literal["discover", "identify", "enforce"]
    status: RunStatus
    detail: str


class ToolEnforcementOutcome(StrictModel):
    target_tool: str
    status: RunStatus
    rule_count: int
    scenario_count: int
    canonical_cases_passed: int
    canonical_cases_total: int
    compilation: dict[str, bool] = Field(default_factory=dict)
    native_verification: RunStatus = "not_run"
    artifact_directory: str


class ActionControlReport(StrictModel):
    project: str
    source: str
    phases: list[PhaseOutcome]
    inventory: CapabilityInventory
    control_analysis: ControlAnalysis
    enforcement: list[ToolEnforcementOutcome]
    overall_status: RunStatus


class PolicyWorkspaceConfig(StrictModel):
    api_version: Literal["policyauthor.dev/workspace/v1alpha1"] = (
        "policyauthor.dev/workspace/v1alpha1"
    )
    project: str
    source_root: str
    source_mode: Literal["workspace_relative", "external_absolute"]
    targets: list[str] = Field(
        default_factory=lambda: ["opa", "agent-hooks", "acs"],
        min_length=1,
    )
    policy_directory: str = "policies"
    test_directory: str = "tests"
    generated_directory: str = "generated"

    @model_validator(mode="after")
    def unique_targets(self) -> PolicyWorkspaceConfig:
        if len(self.targets) != len(set(self.targets)):
            raise ValueError("workspace targets must be unique")
        return self


class FindingDisposition(StrictModel):
    finding_id: str = Field(min_length=1)
    disposition: Literal["resolved", "accepted_risk", "false_positive"]
    rationale: str = Field(min_length=12)
    owner: str | None = None
    expires_at: datetime | None = None
    evidence: list[str] = Field(default_factory=list)
    compensating_controls: list[str] = Field(default_factory=list)


class ApprovalEvidence(StrictModel):
    reviewer: str = Field(min_length=1)
    reviewer_role: str | None = None
    approved_at: str
    rationale: str = Field(min_length=1)
    source_revision: str
    policy_digest: str
    test_digest: str
    test_result_digest: str
    project_digest: str = ""
    context_digest: str = ""
    workspace_config_digest: str = ""
    findings_digest: str = ""
    adapter_identities: dict[str, str] = Field(default_factory=dict)
    snapshot_digest: str = ""
    product_version: str = ""
    approval_packet_digest: str = ""
    semantic_acknowledgements: list[str] = Field(default_factory=list)
    finding_dispositions: list[FindingDisposition] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_identities(self) -> ApprovalEvidence:
        _require_unique(
            self.semantic_acknowledgements,
            "semantic acknowledgement",
        )
        _require_unique(
            [item.finding_id for item in self.finding_dispositions],
            "finding disposition id",
        )
        _require_unique(self.targets, "approval target")
        return self


class ActionReview(StrictModel):
    tool: str
    risk: Literal["read", "write", "consequential-write", "unknown"]
    mutates_state: bool | None = None
    requires_approval: bool | None = None
    review_status: Literal[
        "not_applicable",
        "needs_review",
        "approved",
        "rejected",
    ]
    source_targets: list[SourceReference] = Field(default_factory=list)
    proposed_rule_ids: list[str] = Field(default_factory=list)
    questions: list[str] = Field(default_factory=list)
    blocking_findings: list[str] = Field(default_factory=list)
    notes: str = ""
    approval: ApprovalEvidence | None = None

    @model_validator(mode="after")
    def require_unique_identities(self) -> ActionReview:
        _require_unique(self.proposed_rule_ids, "proposed rule id")
        _require_unique(self.blocking_findings, "blocking finding id")
        return self


class PolicyWorkspaceReview(StrictModel):
    project: str
    actions: list[ActionReview]
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_actions(self) -> PolicyWorkspaceReview:
        _require_unique([action.tool for action in self.actions], "review action tool")
        return self
