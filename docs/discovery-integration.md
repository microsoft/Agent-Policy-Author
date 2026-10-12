# Using Agent Policy Author with your own code

Agent Policy Author discovers tools statically. It does not import application
modules, execute repository code, or provide a runtime tool decorator. Keep
using the decorator or registration API supplied by your agent framework. The
scanner recognizes supported names by their final symbol, so both `@tool` and
`@framework.tool` match.

There are four integration options:

1. Use a recognized Python or TypeScript/JavaScript decorator or registration.
2. Add a language-neutral tool inventory when source syntax is unsupported or
   explicit metadata is preferable.
3. Provide an OpenAPI document for HTTP tools.
4. Provide an authoritative Agent Policy Author `project.yaml`,
   `project.yml`, or `project.json`.

The language-neutral inventory is the most portable option for custom
frameworks and languages without a source adapter.

## Python

### Decorated functions

Top-level synchronous and asynchronous functions are discovered when decorated
with `tool`, `function_tool`, `kernel_function`, or `ai_function`:

```python
from typing import Literal

from my_agent_framework import tool


@tool
def transfer_inventory(
    item_id: str,
    quantity: int,
    destination: Literal["store", "warehouse"],
    notify: bool = False,
) -> None:
    """Transfer inventory to another location."""
    ...
```

Discovery derives:

- the tool name from the function name;
- the description from the first docstring line;
- the input schema and required fields from parameters, annotations, and
  defaults;
- the handler and exact source span;
- an initial risk classification from the name and description.

Recognized annotations include `str`, `int`, `float`, `bool`, list-like
collections, mappings, and homogeneous `Literal[...]` values. Unknown
annotations remain valid properties with an unconstrained schema. Decorated
Python methods nested inside classes are not currently discovered; use a
top-level decorated function, a constructor registration, or an inventory
file for those tools.

### Constructor registrations

Existing calls whose final callee is `ToolSpec` or `ToolDefinition` are also
recognized. Values used for discovery must be literals:

```python
inventory_transfer = ToolSpec(
    name="transfer_inventory",
    description="Transfer inventory to another location.",
    domain="inventory",
    mutating=True,
    requires_approval=True,
    handler=transfer_inventory,
    input_schema={
        "type": "object",
        "properties": {
            "item_id": {"type": "string"},
            "quantity": {"type": "integer"},
        },
        "required": ["item_id", "quantity"],
        "additionalProperties": False,
    },
)
```

`ToolSpec` and `ToolDefinition` are recognized source patterns, not classes
that applications must import from Agent Policy Author.

## TypeScript and JavaScript

### Decorated functions and methods

Functions and class methods are discovered when decorated with `tool`,
`functionTool`, `function_tool`, `kernelFunction`, `kernel_function`,
`aiFunction`, or `ai_function`:

```typescript
class IncidentTools {
  /** Close an incident. */
  @kernelFunction()
  async closeIncident(
    incidentId: string,
    resolution: "fixed" | "mitigated",
    notify?: boolean,
    retryCount = 3,
  ): Promise<void> {
    // Application implementation.
  }
}
```

The adapter recognizes primitive annotations, literal unions, optional and
defaulted parameters, inferred primitive defaults, async functions, and source
spans. Plain JavaScript without annotations generally provides less schema
detail; use an inline schema or inventory file when the complete input
contract matters.

### Factory registrations

Calls to `tool`, `functionTool`, `function_tool`, `defineTool`, or `createTool`
are discovered when passed an inline object:

```typescript
export const sendMessage = tool({
  name: "send_message",
  description: "Send a message.",
  inputSchema: {
    type: "object",
    properties: {
      recipient: {type: "string"},
      message: {type: "string"},
    },
    required: ["recipient", "message"],
    additionalProperties: false,
  },
  mutatesState: true,
  requiresApproval: true,
  execute: sendMessageHandler,
});
```

The schema may be supplied as `inputSchema`, `input_schema`, `parameters`, or
`schema`. Mutation and approval metadata may use camelCase or snake_case.

## Language-neutral tool inventory

Add a JSON or YAML document containing a `tools` array. The versioned contract
is [`schemas/tool-inventory.v1.schema.json`](../schemas/tool-inventory.v1.schema.json):

```json
{
  "schemaVersion": "1.0",
  "generator": {
    "name": "my-agent"
  },
  "tools": [
    {
      "id": "inventory.transfer",
      "name": "transfer_inventory",
      "description": "Transfer inventory to another location.",
      "language": "go",
      "framework": "custom-agent",
      "handler": "inventory.Transfer",
      "inputSchema": {
        "type": "object",
        "properties": {
          "item_id": {"type": "string"},
          "quantity": {"type": "integer"}
        },
        "required": ["item_id", "quantity"],
        "additionalProperties": false
      },
      "mutatesState": true,
      "requiresApproval": true,
      "source": {
        "path": "internal/inventory/tools.go",
        "startLine": 42
      }
    }
  ]
}
```

Use a stable `id` when the same logical tool may appear in source, generated
metadata, or multiple manifests. Explicit `mutatesState` and
`requiresApproval` values override name-based risk inference.

## OpenAPI

Each OpenAPI `GET`, `POST`, `PUT`, `PATCH`, or `DELETE` operation becomes a
tool. `operationId` is used as the tool name when present; otherwise a name is
derived from the HTTP method and path. Request schemas are normalized into the
tool input schema.

Use stable, descriptive `operationId` values and summaries:

```yaml
openapi: 3.1.0
info:
  title: Inventory API
  version: 1.0.0
paths:
  /inventory/transfers:
    post:
      operationId: transfer_inventory
      summary: Transfer inventory to another location.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                item_id:
                  type: string
                quantity:
                  type: integer
              required: [item_id, quantity]
```

## Risk classification

Explicit manifest or registration metadata is preferred. Without it, discovery
uses the name, description, and HTTP method:

- names beginning with `get`, `list`, `read`, `search`, `find`, `fetch`, or
  `inspect`, and HTTP `GET`, `HEAD`, or `OPTIONS`, are reads;
- names beginning with `prepare`, `confirm`, or `validate` are writes;
- action words such as `apply`, `create`, `delete`, `deploy`, `disable`,
  `execute`, `publish`, `remove`, `revoke`, `send`, `submit`, `suspend`,
  `terminate`, `transfer`, `update`, or `write` indicate consequential writes;
- other HTTP `POST`, `PUT`, and `PATCH` operations are writes;
- anything else remains `unknown` and requires review.

## Identity and reconciliation

Tools are reconciled by canonical identity, not only by display name. An
inventory `id` is the canonical identity; source-discovered tools default to
their declared name. Metadata priority is:

`project > runtime manifest > constructor > manifest > OpenAPI > decorator > heuristic`

Contributions with the same canonical identity are merged and retain
structured provenance. Different canonical identities with the same declared
name are not silently merged; each receives a deterministic suffix and
discovery emits a warning.

## Run discovery

Install Agent Policy Author, then point it at the application root:

```powershell
pipx install "git+https://github.com/microsoft/Agent-Policy-Author.git"
policy-author discover C:\path\to\your-agent
policy-author workbench C:\path\to\your-agent
```

Discovery scans `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mts`, `.cts`, `.json`,
`.jsonl`, `.yaml`, and `.yml` inputs within bounded limits. Generated,
dependency, hidden, and symlinked paths are excluded.

If no tools are found:

- verify that the decorator or factory's final symbol is supported;
- verify that Python decorators are on top-level functions;
- use literal constructor or factory metadata where required;
- add a language-neutral inventory for unsupported syntax or languages;
- implement and register a custom adapter through
  `DiscoveryAdapterRegistry` when native source analysis is needed.
