# Agent Policy Author quick run with a realistic incident agent

This PowerShell guide runs Agent Policy Author against the included synthetic
incident-response agent. The target is a standalone application with two
agentic workflows, 16 tool calls, approval-bound mutations, synthetic state,
and Agent Hooks traces.

Everything is installed beneath one disposable directory. The application and
Policy Author use separate virtual environments outside the copied source tree
so discovery does not scan installed dependencies.

The example uses only synthetic data and local files. It does not call cloud
services, use credentials, deploy policies, or contact real responders.

## Paste-ready setup and launch

Paste this entire block into Windows PowerShell. It creates a uniquely named
disposable directory, clones the current product, creates separate virtual
environments for the target application and Policy Author, installs both,
runs the standalone incident workflow and its tests, and opens the latest
full-screen Policy Author workbench with guided rule management.

```powershell
$ErrorActionPreference = "Stop"

function Assert-NativeSuccess {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE."
    }
}

foreach ($Command in @("python", "git")) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Required command is not available: $Command"
    }
}

$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$Root = Join-Path $env:TEMP "apa-$RunId"
$Repo = Join-Path $Root "Agent-Policy-Author"
$Source = Join-Path $Root "incident-response-agent"
$AgentVenv = Join-Path $Root "agent-venv"
$PolicyVenv = Join-Path $Root "policy-author-venv"
$Workspace = Join-Path $Source ".agent-policy"
$Runs = Join-Path $Root "runs"
$CheckoutRun = Join-Path $Runs "checkout-latency"

New-Item -ItemType Directory -Path $Root | Out-Null

git -c core.longpaths=true clone --depth 1 `
    https://github.com/veersingh_microsoft/Agent-Policy-Author.git `
    $Repo
Assert-NativeSuccess "Repository clone"
$RepoStatus = git -C $Repo status --porcelain
Assert-NativeSuccess "Repository integrity check"
if ($RepoStatus) {
    throw "Repository checkout is incomplete or unexpectedly modified."
}
if (-not (Test-Path (Join-Path $Repo ".git\index"))) {
    throw "Repository checkout is missing its Git index."
}
$ProductCommit = git -C $Repo rev-parse --short HEAD
Assert-NativeSuccess "Product revision check"

Copy-Item `
    (Join-Path $Repo "examples\incident-response-agent") `
    $Source `
    -Recurse

python -m venv $AgentVenv
Assert-NativeSuccess "Incident-agent virtual environment creation"
python -m venv $PolicyVenv
Assert-NativeSuccess "Policy Author virtual environment creation"

$AgentPython = Join-Path $AgentVenv "Scripts\python.exe"
$Agent = Join-Path $AgentVenv "Scripts\incident-agent.exe"
$PolicyPython = Join-Path $PolicyVenv "Scripts\python.exe"
$PolicyAuthor = Join-Path $PolicyVenv "Scripts\policy-author.exe"

& $AgentPython -m pip install --quiet -e $Source
Assert-NativeSuccess "Incident-agent installation"
& $PolicyPython -m pip install --quiet `
    $Repo
Assert-NativeSuccess "Policy Author installation"

& $Agent demo `
    --scenario checkout-latency `
    --output $CheckoutRun
Assert-NativeSuccess "Incident-agent demo"

Push-Location $Source
try {
    & $AgentPython -m unittest discover -s tests -v
    Assert-NativeSuccess "Incident-agent tests"
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Disposable root: $Root" -ForegroundColor Cyan
Write-Host "Product commit: $ProductCommit" -ForegroundColor Cyan
Write-Host "Policy workspace: $Workspace" -ForegroundColor Cyan
Write-Host ""
Write-Host "In the workbench:" -ForegroundColor Yellow
Write-Host "  1. Select page_on_call."
Write-Host "  2. Open Manage rules."
Write-Host "  3. Add, modify, or delete rules using the guided fields."
Write-Host "  4. Requested arguments are agent input; trusted context is runtime supplied."
Write-Host "  5. For 'is in' or 'is not in', enter comma-separated comparison values."
Write-Host "  6. Incompatible comparison values are blocked with field-specific guidance."
Write-Host "  7. Rule IDs are generated automatically when new rules are saved."
Write-Host "  8. Compact action bars keep Save and Cancel visible in small terminals."
Write-Host "  9. Save the rule, edit behavioral tests if needed, and run tests."
Write-Host " 10. Approve requires passing tests and at least one explicit rule."
Write-Host "     A policy may contain one or many rules; an allow rule is optional."
Write-Host "     Approve all is enabled only when every policy is eligible for approval."
Write-Host " 11. Compile, then use Export to download an engine-ready policy ZIP."
Write-Host "     Choose Microsoft Agent Governance Toolkit (AGT / ACS) for AGT."
Write-Host ""
Write-Host "Opening the full-screen workbench..." -ForegroundColor Cyan

& $PolicyAuthor workbench `
    $Source `
    --targets opa,acs `
    --interactive
Assert-NativeSuccess "Policy Author workbench"
```

After quitting the workbench, reopen the same workspace with:

```powershell
& $PolicyAuthor workbench $Workspace --interactive
```

When finished, remove this specific disposable run:

```powershell
Remove-Item -LiteralPath $Root -Recurse -Force
```

## Prerequisites

- Windows PowerShell
- Python 3.11, 3.12, or 3.13
- Git

```powershell
python --version
git --version
```

## 1. Create isolated environments

```powershell
$Root = Join-Path $env:TEMP "agent-policy-author-incident-quickrun"
$Repo = Join-Path $Root "Agent-Policy-Author"
$Source = Join-Path $Root "incident-response-agent"
$AgentVenv = Join-Path $Root "agent-venv"
$PolicyVenv = Join-Path $Root "policy-author-venv"
$Workspace = Join-Path $Source ".agent-policy"
$Runs = Join-Path $Root "runs"

if (Test-Path $Root) {
    throw "Quick-run directory already exists: $Root. Run the cleanup command first or choose another Root."
}

New-Item -ItemType Directory -Path $Root | Out-Null

git -c core.longpaths=true clone --depth 1 `
    https://github.com/veersingh_microsoft/Agent-Policy-Author.git `
    $Repo
if ($LASTEXITCODE -ne 0) {
    throw "Repository clone failed with exit code $LASTEXITCODE."
}

$RepoStatus = git -C $Repo status --porcelain
if ($LASTEXITCODE -ne 0 -or $RepoStatus) {
    throw "Repository checkout is incomplete or unexpectedly modified."
}
if (-not (Test-Path (Join-Path $Repo ".git\index"))) {
    throw "Repository checkout is missing its Git index."
}

Copy-Item `
    (Join-Path $Repo "examples\incident-response-agent") `
    $Source `
    -Recurse

python -m venv $AgentVenv
python -m venv $PolicyVenv

$AgentPython = Join-Path $AgentVenv "Scripts\python.exe"
$Agent = Join-Path $AgentVenv "Scripts\incident-agent.exe"
$PolicyPython = Join-Path $PolicyVenv "Scripts\python.exe"
$PolicyAuthor = Join-Path $PolicyVenv "Scripts\policy-author.exe"

& $AgentPython -m pip install --quiet -e $Source
& $PolicyPython -m pip install --quiet `
    $Repo

& $Agent --help
& $PolicyAuthor --version
& $PolicyAuthor --help
```

Confirm that both Python executables are isolated and outside `$Source`:

```powershell
& $AgentPython -c "import sys; print(sys.executable)"
& $PolicyPython -c "import sys; print(sys.executable)"
```

## 2. Run the standalone agent

Run the multi-region checkout incident workflow:

```powershell
$CheckoutRun = Join-Path $Runs "checkout-latency"

& $Agent demo `
    --scenario checkout-latency `
    --output $CheckoutRun
```

The deterministic workflow:

1. correlates checkout and payment alerts;
2. reads health, dependency, deployment, and runbook evidence;
3. creates an incident and bridge;
4. pages the on-call team;
5. creates an emergency change request;
6. shifts regional traffic;
7. rolls back a deployment;
8. verifies recovery thresholds;
9. updates and resolves the incident.

Inspect its results:

```powershell
Get-Content (Join-Path $CheckoutRun "summary.json") -Raw |
    ConvertFrom-Json |
    Format-List

(Get-Content (Join-Path $CheckoutRun "agent-hooks.jsonl")).Count

Get-Content (Join-Path $CheckoutRun "state.json") -Raw |
    ConvertFrom-Json |
    Select-Object version, incidents, traffic, audit_log
```

Expected checkout results:

- incident status `resolved`;
- 16 tool calls;
- 32 Agent Hooks records;
- audited state mutations.

Run the credential-abuse containment workflow:

```powershell
$SecurityRun = Join-Path $Runs "credential-abuse"

& $Agent demo `
    --scenario credential-abuse `
    --output $SecurityRun

Get-Content (Join-Path $SecurityRun "summary.json") -Raw |
    ConvertFrom-Json |
    Format-List
```

Expected security result: the synthetic workload is `quarantined`, while the
incident remains `investigating` for the remaining manual runbook steps.

Run the target application's tests:

```powershell
Push-Location $Source
try {
    & $AgentPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) {
        throw "Incident-agent tests failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
```

## 3. Discover the incident-agent policy surface

Open the interactive workbench against the copied application source:

```powershell
& $PolicyAuthor workbench $Source --targets opa --interactive
```

Expected initial inventory:

```text
Actions inventoried:          16
Governed policies:            10
Supporting/non-policy actions: 6
Blocking findings:             4
```

The four findings are intentional policy-authoring exercises for ordinary
write operations that have no safe synthesized allow rule:

- `create_change_request`
- `create_incident`
- `open_incident_bridge`
- `update_incident`

The application source is the target. In particular, review:

```powershell
Get-Content `
    (Join-Path $Source "src\incident_agent\tools.py") `
    -TotalCount 120

Get-Content `
    (Join-Path $Source "src\incident_agent\orchestrator.py") `
    -TotalCount 160

Get-Content `
    (Join-Path $Source "src\incident_agent\state.py") `
    -TotalCount 180
```

## 4. Exercise selected-policy review and editing

In the workbench:

1. Click `page_on_call` in the left policy navigator.
2. Review the expanded **Policy properties and source mapping** and
   **Decision rules and condition mappings** sections.
3. Use **Policy authoring help** to compare discovered action arguments with
   trusted context and review the canonical rule shape. A policy may contain
   one or many rules and may intentionally have no allow outcome.
4. Expand **Behavioral tests** and **Raw policy YAML** when you need the exact
   source documents.
5. Click **Manage rules**. Choose **Create a new rule** or an existing rule,
   select the decision and all/any matching behavior, and build conditions from
   discovered action arguments and trusted runtime attributes. Field labels
   remain visible after you enter values, and the larger condition panel keeps
   each comparison readable.
6. Use **Add condition**, **Save rule**, or the confirmed **Delete rule** flow
   without editing canonical YAML. Choose **Advanced YAML** only for a deeply
   nested expression that the guided builder intentionally preserves.
7. For **is in** and **is not in**, enter the comparison values in the field
   shown directly below the operator and separate multiple values with commas.
   The compact action buttons preserve more space for reviewing conditions.
8. Comparison values are validated against discovered argument and trusted
   context types. For example, a text field rejects an unquoted numeric value
   and explains how to enter numeric-looking text such as `"123"`.
9. Rule IDs are generated automatically from the decision and business
   justification; policy authors do not enter or maintain them.
10. The compact command bar and fixed modal actions keep primary controls
    visible in an 80-column terminal.

Trusted-context values are supplied by the runtime, not typed by the policy
author. **Context contract** is the advanced integration-owner path for adding
an authoritative attribute after its runtime resolver is implemented.

Click **Run tests** or press `t` to rerun all canonical tests.

## 5. Verify policy-scoped approval

Select `page_on_call` and click **Approve selected**.

The evidence packet starts collapsed so the reviewer fields are immediately
available. Expand it and review the source revision, source targets, workspace
digests, adapter identities, target fidelity, rules, current tests, and
findings. Provide reviewer identity, role, and rationale, then confirm the exact
snapshot digest. This approves only `page_on_call`; it does not approve the
other nine policies. If you choose **Accept temporary risk**, enter the expiry
as `YYYY-MM-DD`, `MM/DD/YYYY`, or a full ISO timestamp; the date-only formats
are interpreted as end-of-day UTC.

Quit and inspect deterministic status:

```powershell
& $PolicyAuthor workbench $Workspace --no-interactive
```

Expected result after approving one selected policy:

```text
Current approvals:         1
Policies needing review:   9
READINESS  NEEDS_REVIEW
```

Readiness remains `NEEDS_REVIEW` because this realistic target deliberately
requires additional policy authoring and review. Reopen the full-screen
workbench at any time:

```powershell
& $PolicyAuthor workbench $Workspace --interactive
```

## 6. Add runtime trace evidence

Copy the checkout trace into the application root only when you explicitly
want runtime observations included in discovery:

```powershell
$Trace = Join-Path $Source "agent-hooks.jsonl"

Copy-Item `
    (Join-Path $CheckoutRun "agent-hooks.jsonl") `
    $Trace

& $PolicyAuthor workbench $Workspace --interactive
```

Remove the copied trace to return to source-only discovery:

```powershell
Remove-Item -LiteralPath $Trace
& $PolicyAuthor workbench $Workspace --interactive
```

The original run remains safely outside `$Source` under `$Runs`.

## 7. Test source-schema evolution and reconciliation

Add a required `escalation_reason` argument to the `page_on_call` tool
contract:

```powershell
$ToolsFile = Join-Path $Source "src\incident_agent\tools.py"
$ToolsSource = Get-Content $ToolsFile -Raw

$ToolsSource = $ToolsSource.Replace(
@'
                "urgency",
                "approval_token",
'@,
@'
                "urgency",
                "escalation_reason",
                "approval_token",
'@
)

$ToolsSource = $ToolsSource.Replace(
@'
            urgency="string",
            approval_token="string",
'@,
@'
            urgency="string",
            escalation_reason="string",
            approval_token="string",
'@
)

Set-Content -LiteralPath $ToolsFile -Value $ToolsSource
```

Reopen the existing workspace:

```powershell
& $PolicyAuthor workbench $Workspace --interactive
```

Expected behavior:

1. readiness becomes `NEEDS_RECONCILIATION`;
2. click **Sync source** and review the displayed before/after schema fields and
   inventory digests;
3. confirm that the reviewed changes should be synchronized and affected
   approvals invalidated;
4. the previous `page_on_call` approval becomes stale;
5. generated fixtures include the new required argument;
6. the authored policy remains available for deliberate reconciliation;
7. tests and approval must be rerun before publication.

Inspect the reconciled schema:

```powershell
Get-Content (Join-Path $Workspace "project.yaml") -Raw
```

Restore the target source from the clean example if you want to repeat the
baseline workflow:

```powershell
Copy-Item `
    (Join-Path $Repo "examples\incident-response-agent\src\incident_agent\tools.py") `
    $ToolsFile `
    -Force

& $PolicyAuthor workbench $Workspace --interactive
```

## 8. Compile after completing all policy work

Compilation is intentionally unavailable until every governed policy has
current passing tests, no unresolved findings, and attributable approval.

After authoring the four incomplete policies and reviewing all ten policies,
run:

```powershell
& $PolicyAuthor workbench $Workspace --no-interactive --require-ready

if ($LASTEXITCODE -ne 0) {
    throw "The workspace is not fully reviewed and ready."
}
```

Then click **Compile bundle** in the workbench. The lower-level automation
equivalent is:

```powershell
& $PolicyAuthor compile-workspace $Workspace
```

Click **Verify bundle** in the workbench. The lower-level automation equivalent
is:

```powershell
$Current = Get-Content `
    (Join-Path $Workspace "generated\current.json") `
    -Raw |
    ConvertFrom-Json

$Bundle = Join-Path `
    (Join-Path $Workspace "generated") `
    $Current.bundle

& $PolicyAuthor verify-bundle $Bundle
```

Expected result:

```text
BUNDLE INTEGRITY VERIFIED
```

## Cleanup

Quit the workbench before deleting the disposable directory:

```powershell
Remove-Item -LiteralPath $Root -Recurse -Force
```
