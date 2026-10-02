# Policy authoring workspace

The `.agent-policy` directory is the developer-managed source of truth for
agent authorization policy.

## Lifecycle

The recommended entry point is:

```powershell
policy-author workbench <source>
```

It creates or reuses the workspace, recomputes canonical tests, verifies
whether recorded approvals are current, and opens a full-screen terminal
workbench when attached to a terminal. The left navigator lists every governed
policy and its current status. Selecting a policy updates the right review pane
without leaving the workspace.

The review pane starts with readable, collapsible sections:

1. **Policy properties and source mapping** pairs each value with guidance on
   what the developer must review or map, including source path, line, symbol,
   and role.
2. **Decision rules and condition mappings** renders nested canonical
   conditions as readable expressions.
3. **Policy authoring help** lists discovered action arguments, trusted context,
   safe authoring steps, and a canonical rule shape.
4. **Findings and review questions** keeps unresolved governance work visible.
5. **Behavioral tests** summarizes case IDs, expected decisions, results, and
   relevant action arguments.
6. **Raw policy YAML** remains collapsed by default for advanced inspection.

The action bar drives the lifecycle: manage the selected policy's rules, edit
tests, inspect or revise the context contract, run tests, approve the selected
policy, synchronize source changes, compile a local publication bundle, and
verify its integrity. **Manage rules** provides guided add, modify, and delete
flows using discovered action arguments and trusted runtime attributes. Policy
authors select trusted attributes but do not supply their runtime values.
Persistent labels identify every field after typing begins, rule details and
conditions use separate panels, and the action controls remain reachable in an
80-column terminal. Fixed and list comparison values are checked against
discovered argument and context types before save. If runtime data still has an
incompatible type, evaluation fails closed to deny rather than interrupting the
workbench or test run. The workbench generates readable unique rule identifiers
when a rule is created, so authors do not manage internal IDs.
**Advanced YAML** remains available for deeply nested expressions, while
**Context contract** is intended for integration owners adding an authoritative
attribute and its runtime resolver. The two-row layout keeps every action
visible in narrow terminals, and the footer includes shortcuts for source
synchronization and bundle verification. Editors validate the canonical schema
before accepting a change. Interactive review never implicitly selects every
workspace policy.

Governance-sensitive operations remain explicit. Source refresh displays exact
before/after contract fields and inventory digests before confirming that
approvals will be invalidated. Approval displays source revision, source
targets, workspace digests, adapters, target fidelity, rules, tests, and
findings before confirming the exact packet digest. Accepted-risk and
false-positive dispositions collect their required rationale and evidence, and
publication has a separate confirmation. The workbench does not infer or
silently accept any of these decisions.

Use `--no-interactive` for one-shot scripts. CI readiness checks should use
`--no-interactive --require-ready`, which exits unsuccessfully unless readiness
is `passed`. Non-TTY execution automatically uses the one-shot readiness report
and prints exact next commands. Use `--interactive` to force the guided mode.
Workbench fails when discovery finds no policy-relevant actions unless
`--allow-no-actions` is supplied explicitly.
The lower-level `init` command has the same default and does not create the
destination workspace after an empty discovery failure.

For an existing workspace, `workbench` first rediscovers the source and
compares normalized tools, schemas, risk metadata, source references, traces,
controls, and context with `project.yaml`. Any delta produces
`discovery-reconciliation.json` and blocks testing, approval, and compilation.
Run `policy-author refresh-workspace <workspace>` to apply the new inventory.
In the workbench, the equivalent **Sync source** action performs this operation
after the reviewer inspects the displayed contract delta and explicitly
confirms it.
Refresh preserves authored policy rules and test intent, fills newly required
fixture arguments, generates comparison policies under
`.artifacts/reconciliation-suggestions`, archives removed-tool artifacts, and
invalidates approval for renewed review. Newly discovered consequential tools
receive separate draft policy and test files; removed tools are moved under
`.artifacts/retired` rather than silently deleted. Missing suggested controls
become reconciliation findings. Approval remains blocked until the controls
are merged or each finding receives a structured false-positive or
accepted-risk disposition. Unknown action impact is also a readiness blocker
and must be classified in source before testing or approval.

The underlying lifecycle remains:

1. `policy-author init <source>` statically discovers actions and drafts policy.
2. `policy-author refresh-workspace <workspace>` reconciles source changes
   when `workbench` reports a discovery delta.
3. `policy-author review <workspace>` shows policies requiring human review,
   focused questions, and the source locations governed by each policy.
4. Developers edit `policies/*.yaml`, `context.yaml`, and `tests/*.yaml`.
5. `policy-author test-workspace <workspace>` evaluates canonical behavior.
6. `policy-author approval-preview <workspace>` writes the complete review
   packet and confirmation digest.
7. `policy-author approve <workspace> --tool <name|all> --reviewer <identity>
   --rationale <reason> --confirm-snapshot <digest>` records attributable,
   packet-bound review evidence.
8. `policy-author compile-workspace <workspace>` builds target artifacts.

Compilation always rejects unapproved policies. Draft rendering is isolated
behind `compile-draft` and `.artifacts/drafts/`. Approval and authoritative
compilation also reject missing, empty, failed, or stale test evidence.
Compilation promotes a bundle only inside `generated/`; it does not deploy to a
remote policy service. Packaged builds produced from dirty source are rejected
unless the caller explicitly supplies `--allow-dirty-product`, and that
development acknowledgement is recorded in the manifest.

## Files

- `policy-author.yaml`: project source and target-engine configuration.
- `project.yaml`: normalized discovered action and context model.
- `actions.yaml`: action inventory and review state.
- `context.yaml`: editable trusted-context contract.
- `review.yaml`: focused questions, warnings, and approval state.
- `approval-packet.json`: complete reviewer-visible evidence and confirmation
  digest.
- `policies/*.yaml`: canonical policy source.
- `tests/*.yaml`: editable allow/deny expectations.
- `generated/bundles/<sha256>/`: immutable authoritative publication bundles.
- `generated/current.json`: atomic pointer to the accepted bundle.
- `generated/<tool>/<target>/`: convenience views of accepted artifacts.
- `generated/compilation-report.json`: state of the accepted publication.
- `generated/last-attempt.json`: latest compilation attempt, successful or not.

## Source targets

Every policy includes:

```yaml
source_targets:
  - path: src/agent/tools/orders.py
    line: 42
    symbol: create_order
    role: tool_registration
```

These references are propagated into generated source maps and Agent Hooks
bindings. They identify the code action governed by the policy and make policy
review traceable back to the repository.

## Review semantics

Generated policies begin with:

```yaml
metadata:
  review_status: needs_review
```

Policy generation is a recommendation, not an approval. Developers should
confirm business intent, trusted context, payload and resource binding, and
expected allow/deny tests before approving the policy.

Approval records the reviewer, optional reviewer role, timestamp, rationale,
source revision, project/context/workspace digests, policy/test/result digests,
finding dispositions, target scope, adapter identities, product version, and
the effective snapshot digest. Editing any bound input invalidates approval.
Accepted-risk dispositions require evidence, a future expiry, and compensating
controls; expiry invalidates the approval. Reviewer identities and roles are
self-declared because this local tool does not authenticate organizational
authority. The accepted-risk fields appear only when that disposition is
selected. Expiry entry accepts `YYYY-MM-DD`, `MM/DD/YYYY`, or a full ISO
timestamp; date-only values are stored as end-of-day UTC.

Finding disposition semantics are serialized canonically for preview,
approval, review, and compilation. Reviewer-derived ownership is stored as
attribution in the approval record but does not rewrite the semantic payload
after confirmation. Rationale, evidence, expiry, compensating controls, or
disposition changes remain approval-invalidating inputs.
Workspaces containing disposition approvals created by an earlier product
version may require one new preview and approval because product-version and
evidence-format changes intentionally invalidate prior snapshots.

The approval packet also identifies `lossy_fail_closed` target translations.
Each `<target>:<rule-id>` must be acknowledged during approval. Compilation
with `--require-exact-semantics` rejects both lossy and unsupported target
semantics. Supply the same acknowledgement flags to `approval-preview` and
`approve`, because the acknowledgement set is bound into the packet digest.
After preview, `approve --packet approval-packet.json` can reuse the reviewed
dispositions and acknowledgements while still requiring reviewer attribution,
rationale, and explicit digest confirmation.
When exact compilation fails, terminal output identifies each affected rule
and its fidelity classification; the JSON report remains available for
automation.

Compilation distinguishes integrity, validation assurance, and rendering.
OPA, ACS, and Cedar can provide native assurance; Agent Hooks and Cerbos
provide contract assurance over the generated integration contract and
resource policy. `validation_not_run` means the required validator was
unavailable. Use `--require-validated` to prevent promotion unless every
selected target satisfies its declared assurance. CLI output labels each
target as `native` or `contract` and separately reports whether every target
received native validation.

Agent Hooks depends on OPA. Target compilation is dependency ordered, and the
generated binding's relative OPA artifact and schema references must resolve
inside the staged tool package before contract validation succeeds.

Every accepted bundle contains `publication-manifest.json` with hashes for all
artifact bytes and the complete approval envelope. Run
`policy-author verify-bundle <bundle-directory>` to detect tampering.
Add `--require-validated` when verification must also reject bundles with
incomplete target validation. Every target package includes
`integration-contract.json`, and the bundle includes
`integration-contracts.json` plus consumer guidance. The installed CLI's
`evaluate-current` command is a fail-closed OPA reference integration. It
validates the action identity and complete arguments against the packaged tool
schema before invoking OPA, so missing, unknown, mistyped, and enum-invalid
arguments are denied before policy evaluation.

The diagnostic `analyze` and `evaluate-engines` paths use the same Draft
2020-12 input gate as `evaluate-current`. Their machine-readable results state
whether a scenario was blocked by schema validation or evaluated by canonical
policy, preventing a schema denial from being misreported as a policy failure.

Trace-derived confirmation recommendations are action-chain scoped. A
confirmation tool contributes rules only when every successful trace for the
governed action places that confirmation before the action.

Workspace source paths are relative to the workspace whenever possible.
Moving the source tree and workspace together therefore preserves the binding.
Cross-drive source paths are explicitly external and absolute; unsafe legacy
workspaces must be reinitialized. Python, JSON, JSONL, YAML, and other
supported discovery inputs are included in source revision hashing. Editing an
Agent Hooks JSONL trace therefore invalidates stale test and approval evidence.
Malformed candidate Agent Hooks JSON or JSONL inputs fail discovery explicitly;
JSONL errors identify the source line and column rather than silently removing
the trace from the inventory.

Identity-bearing collections are validated before workflow execution.
Duplicate policy rule IDs, tool names, context paths, trace IDs, review action
tools, finding dispositions, semantic acknowledgements, targets, and test IDs
are rejected with the duplicate identity named in a concise product error,
without framework-internal validation dumps.

`review`, `workbench`, approval preview, and compilation use current evidence
rather than only the recorded `review_status`. A recorded approval whose
source, inventory, policy, tests, configuration, target adapters, or risk
dispositions changed is displayed as effectively stale and cannot compile.
