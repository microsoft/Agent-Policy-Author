# Governance roadmap

This document tracks governance design work that should remain visible and
reviewable in the open-source project.

## G-001: Make compilation authority explicit

**Status:** Implemented

**Target milestone:** `v0.6.0`

**Labels:** `governance`, `security-design`, `breaking-change`

### Problem

The workspace path requires current tests, explicit approval, and fresh source,
policy, test, and test-result digests before `compile-workspace` emits
artifacts. Adapter developers also need a lower-level renderer that can inspect
target compatibility before that governance lifecycle is complete.

The local-only product now separates those purposes:

- `compile-workspace` is the authoritative reviewed compiler.
- `compile-draft` and `AuthoringService.compile_draft` are explicitly
  unapproved renderers.
- Draft output is isolated beneath `.artifacts/drafts/`.
- Draft manifests record `authority: draft`, `approved: false`, and the policy
  review status.
- The project has no HTTP API or web server.

### Acceptance criteria

- [x] Compilation entry points declare authoritative or draft intent.
- [x] Authoritative compilation uses the workspace evidence checks.
- [x] Draft artifacts are labeled unapproved.
- [x] Draft artifacts are written to a separate location.
- [x] CLI and SDK draft behavior have regression coverage.
- [x] Documentation distinguishes rendering compatibility from approval.
