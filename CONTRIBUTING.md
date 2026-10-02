# Contributing

Agent Policy Author is structured as a small typed Python package so new
discovery adapters, policy patterns, and target engines can be added
independently.

## Local setup

```powershell
git clone https://github.com/veersingh_microsoft/Agent-Policy-Author.git
cd Agent-Policy-Author
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

Before submitting a change:

```powershell
.\.venv\Scripts\ruff check .
.\.venv\Scripts\mypy src tests
.\.venv\Scripts\pytest
.\.venv\Scripts\python -m build
```

Dependencies are locked in `requirements.lock`. After changing
`pyproject.toml`, regenerate the lock from a clean supported Python environment
and validate it on Python 3.11 and 3.13 before submitting the change.

Release tags use the format `policy-author-v<version>`. The release workflow
builds distributions, generates a CycloneDX SBOM, creates GitHub build and SBOM
attestations, and publishes the artifacts to a GitHub release.

Changes to policy semantics should include:

- a canonical evaluator test;
- adapter compilation coverage;
- at least one valid and one adversarial scenario;
- evidence that denied actions do not reach execution.

Discovery changes must remain static and bounded. Do not import or execute the
repository being analyzed.

## Extension points

- `src/policy_authoring/discovery`: source and trace discovery
- `src/policy_authoring/recommendation`: policy and gate inference
- `src/policy_authoring/adapters`: target-language compilation
- `src/policy_authoring/evaluation`: native-engine parity testing

Generated target policies must retain canonical rule identifiers and must fail
explicitly when required behavior cannot be represented.

## Contributor License Agreement

Most contributions require agreement to a Contributor License Agreement (CLA)
declaring that you have the right to, and do, grant Microsoft the rights to use
your contribution. For details, visit
<https://cla.opensource.microsoft.com/>.

When you submit a pull request, a CLA bot will automatically determine whether
you need to provide a CLA and decorate the pull request with the appropriate
status check. Follow the bot's instructions if a signature is required. You
only need to complete this process once for Microsoft repositories using this
CLA.

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
