# Cross-engine product evaluation

This evaluation measures the complete product behavior rather than testing
only target-language rendering.

## Evaluation pipeline

```text
example agent source + Agent Hooks trace
                    |
                    v
        bounded static discovery
                    |
          +---------+---------+
          |                   |
          v                   v
 proposed canonical policy  functional gates
          |
          v
 OPA / Cedar / Cerbos / ACS / Agent Hooks artifacts
          |
          v
 identical valid and mutated tool-call scenarios
          |
          v
 decision parity + side-effect enforcement report
```

The input is `examples/discovery-agent`. The product extracts the decorated
tool definitions without importing the module, imports the recorded Agent
Hooks workflow, derives trusted preparation and confirmation context, and
generates the proposed policy.

## Generated functional gates

The product proposes gates for:

1. validating the tool call against the discovered schema;
2. binding tool arguments to trusted preparation state;
3. requiring positive confirmation bound to the same operation and digest;
4. evaluating policy at `pre_tool_call`;
5. invoking `apply_update` only after an explicit allow decision.

The evaluation treats ACS and Agent Hooks as runtime integration contracts, not
independent policy engines. Their paths are tested with the generated OPA
policy and their respective context mappings.

## Scenario set

The harness evaluates:

- a valid prepared and confirmed action;
- digest, value, and document mutations;
- a route shift;
- absent and explicitly negative confirmation;
- cross-operation and replayed confirmation;
- missing trusted preparation state;
- an unknown tool argument blocked by the generated schema gate.

For every target, the inert side-effect ledger is represented by the
`side_effect_executed` result. Only an effective allow may execute.

## Running locally

```powershell
docker pull ghcr.io/cerbos/cerbos:0.46.0
.\.venv\Scripts\policy-author evaluate-engines `
  examples\discovery-agent `
  --tool apply_update `
  --targets opa,cedar,cerbos,agent-hooks,acs `
  --output .policy-evaluation
```

The command requires native `opa` and `cedar` executables and a working Docker
daemon. It starts and removes a temporary Cerbos container automatically.
Use `--generate-only` when only portable target artifacts are required, or
when the selected native engines are not installed.

Generation and native verification now have independent statuses.
`--generate-only` reports `compilation_status=passed`,
`evaluation_status=not_run`, and `overall_status=partial`; it never reports a
verification pass without scenarios and engine results. When a trace is not
available, deterministic scenarios are generated from the tool schema,
trusted context contract, and generated policy rules. ACS sample inputs use
the same synthetic context and no longer require a successful trace.

## Current result

The code-derived proposal contains 10 inferred blocking or escalation rules,
one explicit allow rule, and 13 functional gates. The 11 scenarios produced 66
target results:

| Target | Passed |
|---|---:|
| Canonical evaluator | 11/11 |
| OPA | 11/11 |
| Cedar | 11/11 |
| Cerbos | 11/11 |
| Agent Hooks + OPA | 11/11 |
| ACS + OPA | 11/11 |

All invalid actions were blocked before the simulated side effect. The valid
action was allowed by every target.

This result demonstrates semantic parity for the tested policy subset. It does
not prove compatibility with every target-language feature or every agent
framework.
