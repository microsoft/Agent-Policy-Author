# Security policy

## Supported versions

Security fixes are provided for the latest released minor version.

| Branch or version | Supported |
|---|---|
| `main` pre-release | Yes |
| Published releases | None yet |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's **Report a vulnerability** option on the repository Security tab:

<https://github.com/veersingh_microsoft/Agent-Policy-Author/security/advisories/new>

Include:

- the affected version or commit;
- the affected CLI command, workspace workflow, or generated target;
- reproduction steps or a minimal repository;
- expected and observed behavior;
- potential impact;
- any suggested remediation.

You should receive an acknowledgment within five business days. Disclosure
timing will be coordinated after the issue is validated and a remediation plan
is available.

## Scope

Reports about policy bypass, cross-project isolation, unsafe artifact
generation, trust-boundary confusion, approval-evidence integrity, or discovery
path escapes are in scope.

The CLI records reviewer identities and roles but does not authenticate them.
Repository permissions, protected branches, signed release processes, and
organizational authorization remain external controls. Bundle verification
proves integrity; it proves target validation only when
`fully_validated: true` or `verify-bundle --require-validated` succeeds.

Generated policy recommendations are not security certifications. A policy that
is incomplete because a developer did not review or integrate it at the actual
runtime enforcement point is not, by itself, a product vulnerability.
