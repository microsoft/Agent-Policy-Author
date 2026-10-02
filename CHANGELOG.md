# Changelog

All notable changes to Agent Policy Author are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- TTY-aware interactive `workbench` lifecycle for policy inspection and
  editing, source reconciliation, canonical testing, governed finding
  dispositions, packet-bound approval, and immutable bundle publication.
- Explicit `--interactive` and `--no-interactive` workbench modes so terminal
  users receive a persistent guided experience while scripts and CI retain
  deterministic one-shot output.
- `workbench --no-interactive --require-ready` for CI readiness gates.
- Dirty packaged-build protection for authoritative compilation, with an
  explicit local-development acknowledgement recorded in bundle provenance.
- Mandatory normalized source reconciliation for existing workspaces, with
  actionable tool/schema/context/trace deltas and an explicit
  `refresh-workspace` workflow.
- Reconciliation suggestions for changed policies and archival of removed-tool
  policy/test artifacts.
- Enforceable reconciliation findings for suggested controls that remain
  absent from the authored policy.
- `approve --packet` reuse of reviewed finding dispositions and semantic
  acknowledgements.
- Explicit native-versus-contract assurance labels in compilation and bundle
  verification output.
- Strict `workbench` empty-discovery behavior with an intentional
  `--allow-no-actions` override.
- Strict `init` empty-discovery behavior with an intentional
  `--allow-no-actions` override and no partial workspace creation.
- Failed canonical test case details in terminal output.

### Changed

- Policies with one or more explicit rules may now be approved without an
  allow outcome. Deny-, warn-, escalate-, and transform-only policies remain
  valid when their behavioral tests pass.
- Approval preview, approval, workbench, and compilation now share canonical
  finding-disposition semantics; reviewer-derived ownership remains recorded
  attribution without changing the confirmed snapshot.
- Action-control analysis, cross-engine evaluation, and the OPA reference
  consumer now share complete Draft 2020-12 action-input validation and report
  whether schema validation or canonical policy produced the decision.
- Workbench, review, testing, approval, and compilation fail closed when the
  live action inventory differs from the reviewed workspace.
- Workspace refresh preserves authored rules, merges discovered context, fills
  newly required fixture arguments, and invalidates prior approval.
- Effective review removes stale `incomplete_policy_synthesis` findings once
  the authored policy has at least one explicit decision rule, and readiness
  summaries count only findings still awaiting disposition.
- Generated valid fixtures jointly satisfy enum restrictions and trusted-state
  bindings.
- Consequential verb inference recognizes underscore-separated deployment
  actions plus revoke, disable, suspend, and terminate operations; merged
  source references keep path and line provenance atomic.
- Unknown-risk actions now block readiness until explicitly classified.
- Trace-derived confirmation controls are scoped to traces containing the
  governed action instead of leaking across unrelated tools.
- The OPA reference consumer validates the action identity and complete
  argument payload against the packaged JSON Schema before engine invocation.
- Review output distinguishes approved packet digests from the prospective
  packet digest, and line-less manifest references no longer fabricate line 1.
- Cross-engine diagnostics generate mutations only for fields present in the
  discovered action and trusted context.
- Review output reports effective approval state rather than stale recorded
  metadata.
- Approval preview now prints required semantic acknowledgement flags and
  explains that the same flags are bound into preview and approval.
- Missing source references and undeclared approval requirements use explicit
  human-readable labels.
- Exact-semantics compilation failures identify affected rule IDs and fidelity
  classifications directly in terminal output.
- Model validation failures use concise product errors without Pydantic input
  dumps or documentation URLs.

### Fixed

- Reconciliation findings with valid false-positive or accepted-risk
  dispositions no longer make a successful approval immediately stale, and
  compilation evaluates the same effective dynamic finding set as review.
- The documented `analyze` workflow now applies the generated schema gate, so
  unknown-argument scenarios are correctly denied before canonical policy
  evaluation.
- Agent Hooks bindings now resolve their companion OPA policy relative to the
  published tool package, validate all referenced artifacts, and compile
  dependencies before dependants.
- JSONL trace inputs now participate in source revision hashing and invalidate
  stale test and approval evidence.
- Malformed candidate Agent Hooks JSON and JSONL traces fail discovery
  explicitly with source location details.
- Duplicate audit identities are rejected across canonical rules, projects,
  context contracts, traces, reviews, approvals, and policy tests.

## 0.7.0 - 2026-09-25

### Added

- Relocatable workspace source bindings with explicit external-source mode.
- Reviewer approval packets and mandatory snapshot confirmation.
- Evidence, expiry, compensating-control, and reviewer-role requirements for
  finding dispositions.
- Explicit semantic fidelity, lossy-translation acknowledgement, and an exact
  semantics publication profile.
- Target dependency contracts, Agent Hooks-to-OPA evaluator binding, and
  contract assurance for Agent Hooks and Cerbos.
- Per-target integration contracts and a fail-closed OPA reference consumer.
- Validator and build provenance in authoritative publication manifests.

### Changed

- Bundle verification now distinguishes integrity from complete target
  validation.
- Convenience target views are exact projections of the current bundle.
- Current publication state is separate from the latest compilation attempt.
- Approval expiry and source relocation are checked during later workflow
  stages.

### Fixed

- Repeated unchanged compilation retains a deterministic bundle identity while
  full manifests still bind run-specific validator timestamps.
- No-rule policy generation no longer creates contradictory allow tests and is
  blocked from approval until an allow path is authored.
- Runtime bundle resolution, tamper, engine, timeout, and malformed-response
  failures are fail-closed.

## 0.6.0 - 2026-09-25

### Added

- MIT licensing and open-source security reporting guidance.
- CI, dependency locking, SBOM generation, and release attestations.
- Explicit draft compilation metadata and isolated draft artifact paths.
- Evidence-bound approvals covering project, context, workspace configuration,
  findings, adapter identities, product version, and the effective snapshot.
- Immutable digest-addressed publication bundles, artifact hashes, atomic
  current pointers, tamper verification, and failure quarantine.
- Explicit target capability contracts and reproducible evaluation evidence.

### Changed

- The low-level renderer is now named `compile-draft`; the former `compile`
  command remains as a deprecated compatibility alias. Reviewed output must use
  `compile-workspace`.
- Agent Policy Author is a CLI-only product.
- `context.yaml` is the authoritative workspace context contract.
- Blocking findings require structured per-finding dispositions.
- Discovery imports only explicit root project definitions and excludes
  generated workspace roots.
- Native engine execution is bounded by timeouts and requires strict rule
  attribution when scenarios identify an expected rule.

### Fixed

- Policy persistence is scoped by project, policy name, and version.
- Legacy SQLite policy tables migrate to the project-scoped schema.
- SQLite connections close deterministically.
- Strict mypy findings and package version metadata.
- Cedar and Cerbos `warn` lowering now matches their documented fail-closed
  behavior.
- Failed target validation no longer replaces last-known-good output.
- Low-level CLI failures are rendered as concise command errors instead of
  Python tracebacks.

### Removed

- The local FastAPI server, web studio, server container, and related
  dependencies.

## 0.5.0 - 2026-09-24

### Added

- Guided policy workbench lifecycle.
- Current-test and source-revision binding for approval evidence.
- Portable policy compilation for OPA, Cedar, Cerbos, Agent Hooks, and ACS.
- Static project discovery, canonical policy tests, and source mappings.
