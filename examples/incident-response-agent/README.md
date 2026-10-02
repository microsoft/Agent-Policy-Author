# Synthetic incident-response agent

This standalone, deterministic application is a realistic Agent Policy Author
test target. It models multi-region commerce incident response without calling
live services or requiring credentials.

The checkout workflow searches alerts, reads service and deployment evidence,
creates an incident, opens a bridge, pages responders, creates a change
request, shifts traffic, rolls back a deployment, verifies recovery, publishes
a synthetic status update, and resolves the incident. A second workflow models
credential-abuse containment.

Every tool call emits an Agent Hooks trace. Mutating tools use shared version,
idempotency, mutation-audit, incident-binding, and approval boundaries.

## Run it

```powershell
python -m venv .venv
$Python = ".\.venv\Scripts\python.exe"
$Agent = ".\.venv\Scripts\incident-agent.exe"

& $Python -m pip install -e .
& $Agent demo --scenario checkout-latency --output .runs\checkout-latency
& $Python -m unittest discover -s tests -v
```

The application only mutates files beneath the selected output directory.
Keep the Policy Author virtual environment outside this application root so
source discovery does not scan installed dependencies.

Expected Policy Author inventory:

- 16 discovered actions;
- 10 governed write policies;
- 6 supporting read actions;
- 4 ordinary write actions intentionally requiring explicit policy authoring.

The fixture approval token `APR-CHANGE-001` is synthetic and bound to incident
`INC-1001`. No real credentials, customer data, endpoints, or cloud resources
are used.
