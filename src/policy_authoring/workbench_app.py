# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from rich.console import Group
from rich.markdown import Markdown
from rich.table import Table
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.containers import (
    Container,
    Horizontal,
    Vertical,
    VerticalScroll,
)
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Select,
    Static,
    TextArea,
)

from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    FindingDisposition,
    PolicyRule,
)
from policy_authoring.ingestion.loader import load_policy
from policy_authoring.workspace import (
    approve_workspace,
    build_approval_packet,
    build_workbench_report,
    compile_workspace,
    export_policy_package,
    refresh_workspace,
    verify_publication_bundle,
)

TARGET_LABELS = {
    "opa": "OPA (Rego)",
    "cedar": "Cedar",
    "cerbos": "Cerbos",
    "acs": "Microsoft Agent Governance Toolkit (AGT / ACS)",
    "agent-hooks": "Agent Hooks",
}


def _status_color(status: str) -> str:
    return {
        "passed": "green",
        "approved": "green",
        "needs_review": "yellow",
        "needs_reconciliation": "red",
        "failed": "red",
        "stale": "red",
        "not_run": "yellow",
        "not_applicable": "bright_black",
    }.get(status, "white")


def _generated_rule_id(
    decision: str,
    reason: str,
    existing_ids: set[str],
) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", reason.lower()).strip("-")
    if not slug:
        slug = f"{decision}-rule"
    elif not slug.startswith(f"{decision}-"):
        slug = f"{decision}-{slug}"
    base = slug[:64].rstrip("-")
    candidate = base
    suffix = 2
    while candidate in existing_ids:
        marker = f"-{suffix}"
        candidate = f"{base[: 64 - len(marker)].rstrip('-')}{marker}"
        suffix += 1
    return candidate


def _findings_review(
    warnings: list[str],
    findings: list[str],
    questions: list[str],
) -> Group:
    sections: list[Text] = []

    def append_section(
        title: str,
        values: list[str],
        *,
        style: str,
    ) -> None:
        if not values:
            return
        if sections:
            sections.append(Text())
        heading = Text(title, style=f"bold {style}")
        sections.append(heading)
        for value in values:
            line = Text("  • ", style=style)
            line.append(str(value), style="white")
            sections.append(line)

    append_section("Workspace warnings", warnings, style="yellow")
    append_section("Unresolved findings", findings, style="red")
    append_section("Review questions", questions, style="yellow")
    if not sections:
        sections.append(
            Text(
                "No unresolved findings or review questions.",
                style="green",
            )
        )
    return Group(*sections)


def _operand_text(value: Any) -> str:
    if value.path is not None:
        return str(value.path)
    return json.dumps(value.literal, sort_keys=True)


def format_condition(condition: Condition, depth: int = 0) -> list[str]:
    indent = "  " * depth
    operator = condition.operator.replace("_", " ").upper()
    if condition.operator in {"all", "any", "not"}:
        lines = [f"{indent}{operator}"]
        for child in condition.conditions:
            lines.extend(format_condition(child, depth + 1))
        return lines
    if condition.operator == "exists" and condition.left is not None:
        return [f"{indent}{_operand_text(condition.left)} EXISTS"]
    if condition.operator in {"in", "not_in"} and condition.left is not None:
        values = ", ".join(
            json.dumps(item, sort_keys=True) for item in condition.values
        )
        return [f"{indent}{_operand_text(condition.left)} {operator} [{values}]"]
    if condition.left is not None and condition.right is not None:
        return [
            f"{indent}{_operand_text(condition.left)} {operator} "
            f"{_operand_text(condition.right)}"
        ]
    return [f"{indent}{operator}"]


def policy_property_rows(policy: Any) -> list[tuple[str, str, str]]:
    source = ", ".join(
        " | ".join(
            part
            for part in (
                f"{item.path}:{item.line}" if item.line is not None else item.path,
                f"symbol {item.symbol}" if item.symbol else "",
                f"role {item.role}" if item.role else "",
            )
            if part
        )
        for item in policy.source_targets
    )
    return [
        ("Policy name", policy.metadata.name, "Human-readable policy identity"),
        ("Tool", policy.tool, "Application action this policy governs"),
        (
            "Interception point",
            policy.interception_point,
            "Runtime stage where the decision must be enforced",
        ),
        (
            "Default decision",
            policy.default_decision,
            "Result when no rule matches; deny is the safe default",
        ),
        (
            "Tool schema version",
            policy.tool_schema_version,
            "Source contract version this policy maps to",
        ),
        ("Source mapping", source or "not declared", "Code governed by this policy"),
        (
            "Review status",
            policy.metadata.review_status,
            "Recorded review state; current evidence is checked separately",
        ),
    ]


def _property_table(policy: Any) -> Table:
    table = Table(expand=True, show_lines=True)
    table.add_column("Property", style="bold cyan", width=22)
    table.add_column("Current value", style="white", ratio=2)
    table.add_column("What to review or map", style="bright_black", ratio=3)
    for property_name, value, guidance in policy_property_rows(policy):
        table.add_row(property_name, str(value), guidance)
    return table


def _rule_table(policy: Any) -> Group:
    items: list[Any] = []
    for index, rule in enumerate(policy.rules, start=1):
        heading = Text()
        heading.append(f"Rule {index}: {rule.id}", style="bold cyan")
        heading.append(f"  ->  {rule.decision.upper()}", style="bold")
        items.append(heading)
        items.append(Text(f"Why: {rule.reason}", style="white"))
        items.append(
            Text(
                "\n".join(format_condition(rule.condition)),
                style="bright_white",
            )
        )
        if index != len(policy.rules):
            items.append(Text("-" * 72, style="bright_black"))
    if not items:
        items.append(
            Text(
                "No rules are defined. Add at least one explicit decision rule.",
                "red",
            )
        )
    return Group(*items)


def _authoring_help(
    policy: Any,
    project_document: dict[str, Any],
    context_document: dict[str, Any],
) -> Markdown:
    tool: dict[str, Any] = next(
        (
            item
            for item in project_document.get("tools", [])
            if item.get("name") == policy.tool
        ),
        {},
    )
    schema = tool.get("input_schema", {})
    arguments = sorted(schema.get("properties", {}))
    required = set(schema.get("required", []))
    argument_lines = [
        f"- `action.arguments.{name}`"
        + (" **required**" if name in required else " optional")
        for name in arguments
    ] or ["- No action arguments were discovered."]
    attributes = context_document.get("attributes", [])
    context_lines = [
        f"- `{item.get('path')}` ({item.get('type', 'unknown')})"
        for item in attributes
        if item.get("path")
    ] or ["- No trusted context attributes are currently declared."]
    source_lines = [
        "- `"
        + (
            f"{item.path}:{item.line}" if item.line is not None else str(item.path)
        )
        + "`"
        + (f" symbol `{item.symbol}`" if item.symbol else "")
        for item in policy.source_targets
    ] or ["- No source target is declared."]
    lines = [
        "### Authoring path",
        "1. Inspect the governed handler and identify the exact business condition "
        "that authorizes this action.",
        "2. Choose an action argument that identifies the requested resource or "
        "operation.",
        "3. Map it only to a trusted resource, actor, tenant, approval, or "
        "environment attribute with the same domain meaning.",
        "4. Keep `default_decision: deny`; add the narrowest justified allow rule.",
        "5. Add allow and deny behavioral cases, then run tests before approval.",
        "",
        "**Governed source to inspect**",
        *source_lines,
        "",
        "**Discovered action arguments**",
        *argument_lines,
        "",
        "**Trusted context available for mapping**",
        *context_lines,
        "",
        "**Canonical rule shape**",
        "```yaml",
        "rules:",
        "  - id: allow_when_reviewed_relationship_matches",
        "    decision: allow",
        "    reason: Replace with the reviewed business justification.",
        "    condition:",
        "      operator: equals",
        "      left:",
        "        path: action.arguments.<reviewed_resource_field>",
        "      right:",
        "        path: resource.<trusted_matching_field>",
        "```",
        "The placeholders are intentionally invalid until replaced. Do not infer a "
        "relationship merely because two fields are available. If no trustworthy "
        "counterpart exists, keep the action denied and ask the runtime integration "
        "owner to add an authoritative attribute to the context contract and "
        "resolver before authoring the mapping.",
    ]
    return Markdown("\n".join(lines))


def _test_review(
    raw_tests: str,
    test_result: dict[str, Any] | None,
) -> Group:
    document = yaml.safe_load(raw_tests)
    cases = document.get("cases", []) if isinstance(document, dict) else []
    result_cases = {
        str(item.get("id")): item
        for item in (test_result or {}).get("cases", [])
        if isinstance(item, dict)
    }
    items: list[Any] = []
    for case in cases:
        case_id = str(case.get("id", "unnamed"))
        expected = str(case.get("expected_decision", "not declared"))
        result = result_cases.get(case_id)
        status = (
            "PASS"
            if result and result.get("passed")
            else "FAIL"
            if result
            else "NOT RUN"
        )
        color = "green" if status == "PASS" else "red" if status == "FAIL" else "yellow"
        heading = Text()
        heading.append(case_id, style="bold cyan")
        heading.append(f"  expected {expected.upper()}  ", style="white")
        heading.append(status, style=color)
        items.append(heading)
        context = case.get("context", {})
        action = context.get("action", {}) if isinstance(context, dict) else {}
        arguments = action.get("arguments", {}) if isinstance(action, dict) else {}
        if arguments:
            items.append(
                Text(
                    f"Arguments: {json.dumps(arguments, sort_keys=True)}",
                    style="bright_black",
                )
            )
        if case.get("description"):
            items.append(Text(f"Why: {case['description']}", style="white"))
        if isinstance(context, dict):
            decisive_context = {
                key: value for key, value in context.items() if key != "action"
            }
            action_context = {
                key: value
                for key, value in action.items()
                if key != "arguments"
            }
            if action_context:
                decisive_context["action"] = action_context
            if decisive_context:
                items.append(
                    Text(
                        "Decision context: "
                        + json.dumps(decisive_context, sort_keys=True),
                        style="bright_black",
                    )
                )
        if result and result.get("error"):
            items.append(Text(str(result["error"]), style="red"))
    if not items:
        items.append(Text("No behavioral test cases are defined.", style="red"))
    return Group(*items)


def _approval_packet_review(packet: dict[str, Any]) -> Markdown:
    lines = [
        "### Evidence packet",
        f"- **Project:** `{packet['project']}`",
        f"- **Resolved source:** `{packet['resolved_source']}`",
        f"- **Source revision:** `{packet['source_revision']}`",
        f"- **Product version:** `{packet['product_version']}`",
        f"- **Targets:** {', '.join(packet['targets'])}",
        "",
        "**Adapter identities**",
    ]
    lines.extend(
        f"- `{target}`: `{identity}`"
        for target, identity in sorted(packet["adapter_identities"].items())
    )
    lines.extend(["", "**Workspace digests**"])
    lines.extend(
        f"- `{name}`: `{digest}`"
        for name, digest in sorted(packet["workspace_digests"].items())
    )
    for policy in packet["policies"]:
        lines.extend(
            [
                "",
                f"#### Selected policy: `{policy['tool']}`",
                f"- Policy file: `{policy['policy_path']}`",
                f"- Test file: `{policy['test_path']}`",
                f"- Default decision: `{policy['default_decision']}`",
                f"- Rules: {len(policy['rules'])}",
                f"- Behavioral cases: {len(policy['tests'])}",
                f"- Blocking findings: "
                f"{', '.join(policy['blocking_findings']) or 'none'}",
                "- Source targets:",
            ]
        )
        for target in policy["source_targets"]:
            location = str(target.get("path", "unknown"))
            if target.get("line") is not None:
                location += f":{target['line']}"
            details = [
                value
                for value in (
                    f"symbol {target.get('symbol')}" if target.get("symbol") else "",
                    f"role {target.get('role')}" if target.get("role") else "",
                )
                if value
            ]
            lines.append(
                f"  - `{location}`" + (f" ({', '.join(details)})" if details else "")
            )
        lines.append("- Target fidelity:")
        for target, fidelity in sorted(policy["target_fidelity"].items()):
            lossy = [
                str(item.get("rule_id"))
                for item in fidelity["compatibility"]
                if item.get("fidelity") == "lossy_fail_closed"
            ]
            detail = (
                f"; fail-closed differences: {', '.join(lossy)}" if lossy else ""
            )
            lines.append(
                f"  - `{target}` via `{fidelity['adapter_identity']}`: "
                f"{'compatible' if fidelity['compatible'] else 'incompatible'}"
                f"{detail}"
            )
        test_result = policy.get("test_result") or {}
        lines.append(
            "- Current test result: "
            f"{'passing' if test_result.get('passed') else 'not passing'} "
            f"({len(test_result.get('cases', []))} cases)"
        )
        lines.extend(["", "**Rule logic**", "```yaml"])
        lines.extend(
            yaml.safe_dump(policy["rules"], sort_keys=False).rstrip().splitlines()
        )
        lines.extend(["```", "", "**Behavioral case semantics**", "```yaml"])
        lines.extend(
            yaml.safe_dump(policy["tests"], sort_keys=False).rstrip().splitlines()
        )
        lines.append("```")
    return Markdown("\n".join(lines))


def _schema_delta_lines(before: Any, after: Any) -> list[str]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [
            f"- Before: `{json.dumps(before, sort_keys=True)}`",
            f"- After: `{json.dumps(after, sort_keys=True)}`",
        ]
    before_required = set(before.get("required", []))
    after_required = set(after.get("required", []))
    before_properties = before.get("properties", {})
    after_properties = after.get("properties", {})
    lines = []
    for label, values in (
        ("Required fields added", sorted(after_required - before_required)),
        ("Required fields removed", sorted(before_required - after_required)),
        (
            "Properties added",
            sorted(set(after_properties) - set(before_properties)),
        ),
        (
            "Properties removed",
            sorted(set(before_properties) - set(after_properties)),
        ),
        (
            "Property definitions changed",
            sorted(
                name
                for name in set(before_properties) & set(after_properties)
                if before_properties[name] != after_properties[name]
            ),
        ),
    ):
        if values:
            lines.append(f"- **{label}:** {', '.join(f'`{item}`' for item in values)}")
    return lines or ["- The normalized schema representation changed."]


def _reconciliation_review(reconciliation: dict[str, Any]) -> Markdown:
    lines = [
        "### Source contract changes",
        f"- Reviewed inventory: `{reconciliation['current_digest']}`",
        f"- Newly discovered inventory: `{reconciliation['discovered_digest']}`",
        "",
    ]
    changes = reconciliation["changes"]
    location_only = [
        change
        for change in changes
        if change["kind"] == "tool_changed"
        and set(change.get("fields", [])) <= {"source_line", "source_path"}
    ]
    if location_only:
        lines.extend(
            [
                "#### Source locations shifted",
                "- "
                + ", ".join(f"`{change['tool']}`" for change in location_only)
                + " moved because surrounding source changed. Review these mappings, "
                "but no tool contract field changed.",
                "",
            ]
        )
    for change in changes:
        if change in location_only:
            continue
        kind = str(change["kind"])
        subject = change.get("tool") or change.get("path") or change.get("field") or ""
        heading = kind.replace("_", " ").title()
        lines.append(f"#### {heading}" + (f": `{subject}`" if subject else ""))
        if kind == "tool_changed":
            for field in change["fields"]:
                lines.append(f"- **{field}**")
                if field == "input_schema":
                    lines.extend(
                        "  " + line
                        for line in _schema_delta_lines(
                            change["before"].get(field),
                            change["after"].get(field),
                        )
                    )
                else:
                    before = json.dumps(change["before"].get(field), sort_keys=True)
                    after = json.dumps(change["after"].get(field), sort_keys=True)
                    lines.extend(
                        [
                            f"  - Before: `{before}`",
                            f"  - After: `{after}`",
                        ]
                    )
        elif "before" in change or "after" in change:
            lines.append(
                f"- Before: `{json.dumps(change.get('before'), sort_keys=True)}`"
            )
            lines.append(
                f"- After: `{json.dumps(change.get('after'), sort_keys=True)}`"
            )
        elif "before_digest" in change:
            lines.append(
                "- The normalized collection changed; inspect the affected "
                "source controls or traces before synchronizing."
            )
            lines.append(f"- Before: `{change['before_digest']}`")
            lines.append(f"- After: `{change['after_digest']}`")
        else:
            lines.append(
                "- This item was added or removed from the discovered contract."
            )
        lines.append("")
    lines.append(
        "Synchronizing preserves authored policies where possible, generates "
        "comparison suggestions, and invalidates approvals so affected behavior "
        "must be reviewed again."
    )
    return Markdown("\n".join(lines))


def _policy_list_label(policy: dict[str, Any]) -> Text:
    status = str(policy["status"])
    label = Text()
    label.append(str(policy["tool"]), style="bold")
    label.append("\n")
    label.append(status.replace("_", " ").upper(), style=_status_color(status))
    tests = policy["tests"]
    label.append(f"  |  tests {tests['passed']}/{tests['total']}", "bright_black")
    if policy.get("unresolved_findings"):
        label.append(
            f"  |  {len(policy['unresolved_findings'])} finding(s)",
            "red",
        )
    return label


class MessageScreen(ModalScreen[None]):
    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, title: str, message: str, *, error: bool = False) -> None:
        super().__init__()
        self.dialog_title = title
        self.message = message
        self.error = error

    def compose(self) -> ComposeResult:
        with Container(id="message-dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Static(
                self.message,
                classes="dialog-error" if self.error else "dialog-message",
            )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Close", id="close", variant="primary")

    @on(Button.Pressed, "#close")
    def close_dialog(self) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class CompletionModalScreen(ModalScreen[Any]):
    BINDINGS = [("escape", "cancel_modal", "Cancel")]

    def __init__(self, completion: Callable[[Any], None]) -> None:
        super().__init__()
        self.completion = completion

    def complete(self, result: Any) -> None:
        dismissal = self.dismiss()

        async def finish() -> None:
            await dismissal
            self.completion(result)

        self.app.run_worker(
            finish(),
            group="modal-completion",
            exclusive=True,
        )

    def action_cancel_modal(self) -> None:
        self.complete(None)


class ConfirmScreen(CompletionModalScreen):
    def __init__(
        self,
        title: str,
        message: str,
        confirm_label: str,
        completion: Callable[[bool], None],
    ) -> None:
        super().__init__(completion)
        self.dialog_title = title
        self.message = message
        self.confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Container(id="confirm-dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Static(self.message, classes="dialog-message")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(self.confirm_label, id="confirm", variant="warning")

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(False)

    @on(Button.Pressed, "#confirm")
    def confirm(self) -> None:
        self.complete(True)


class ReconciliationScreen(CompletionModalScreen):
    def __init__(
        self,
        reconciliation: dict[str, Any],
        completion: Callable[[bool | None], None],
    ) -> None:
        super().__init__(completion)
        self.reconciliation = reconciliation

    def compose(self) -> ComposeResult:
        with Container(id="reconciliation-dialog"):
            yield Label("Review and synchronize source changes", classes="dialog-title")
            with VerticalScroll(id="reconciliation-body"):
                yield Static(
                    _reconciliation_review(self.reconciliation),
                    classes="dialog-message",
                )
                yield Checkbox(
                    "I reviewed the source contract changes and understand "
                    "affected approvals will be invalidated.",
                    id="confirm-reconciliation",
                )
            yield Static("", id="reconciliation-error")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Synchronize reviewed changes",
                    id="confirm-reconciliation-sync",
                    variant="warning",
                )

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(None)

    @on(Button.Pressed, "#confirm-reconciliation-sync")
    def confirm(self) -> None:
        if not self.query_one("#confirm-reconciliation", Checkbox).value:
            self.query_one("#reconciliation-error", Static).update(
                "Review the displayed changes and confirm before synchronizing."
            )
            return
        self.complete(True)


class EditorScreen(CompletionModalScreen):
    def __init__(
        self,
        path: Path,
        title: str,
        completion: Callable[[bool], None],
    ) -> None:
        super().__init__(completion)
        self.path = path
        self.dialog_title = title
        self.original = path.read_text(encoding="utf-8")

    def compose(self) -> ComposeResult:
        with Container(id="editor-dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Static(str(self.path), classes="path")
            yield TextArea(
                self.original,
                language="yaml",
                id="yaml-editor",
                show_line_numbers=True,
            )
            yield Static("", id="editor-error")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save and validate", id="save", variant="primary")

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(False)

    @on(Button.Pressed, "#save")
    def save(self) -> None:
        content = self.query_one("#yaml-editor", TextArea).text
        self.path.write_text(content, encoding="utf-8")
        try:
            if self.path.parent.name == "policies":
                load_policy(self.path)
            else:
                import yaml

                parsed = yaml.safe_load(content)
                if not isinstance(parsed, dict):
                    raise ValueError("the YAML document must contain a mapping")
        except (ValueError, OSError, ValidationError) as exc:
            self.path.write_text(self.original, encoding="utf-8")
            self.query_one("#editor-error", Static).update(
                f"Not saved. Fix the YAML and try again.\n{exc}"
            )
            return
        self.complete(True)


class RuleConditionRow(Vertical):
    def __init__(
        self,
        index: int,
        operand_paths: list[str],
        trusted_paths: list[str],
    ) -> None:
        super().__init__(id=f"condition-row-{index}", classes="condition-row")
        self.index = index
        self.operand_paths = operand_paths
        self.trusted_paths = trusted_paths

    def compose(self) -> ComposeResult:
        with Horizontal(classes="condition-heading"):
            yield Label(
                f"Condition {self.index + 1}",
                classes="condition-title",
            )
            yield Button(
                "Remove",
                id=f"remove-condition-{self.index}",
                classes="remove-condition",
                variant="warning",
            )
        with Horizontal(classes="condition-fields"):
            with Vertical(classes="condition-field condition-left"):
                yield Label("Field to evaluate", classes="form-label")
                yield Select(
                    [
                        (
                            (
                                f"{path} (requested argument)"
                                if path.startswith("action.arguments.")
                                else f"{path} (trusted context)"
                            ),
                            path,
                        )
                        for path in self.operand_paths
                    ],
                    prompt="Choose a requested or trusted field",
                    id=f"condition-left-{self.index}",
                )
            with Vertical(classes="condition-field condition-operator"):
                yield Label("Operator", classes="form-label")
                yield Select(
                    [
                        ("equals", "equals"),
                        ("does not equal", "not_equals"),
                        ("is in", "in"),
                        ("is not in", "not_in"),
                        ("exists", "exists"),
                        ("greater than", "greater_than"),
                        ("greater than or equal", "greater_than_or_equal"),
                        ("less than", "less_than"),
                        ("less than or equal", "less_than_or_equal"),
                    ],
                    value="equals",
                    allow_blank=False,
                    id=f"condition-operator-{self.index}",
                )
            with Vertical(
                id=f"condition-kind-field-{self.index}",
                classes="condition-field condition-kind",
            ):
                yield Label("Compare with", classes="form-label")
                yield Select(
                    [
                        ("Trusted context field", "path"),
                        ("Fixed value", "literal"),
                    ],
                    value="path",
                    allow_blank=False,
                    id=f"condition-right-kind-{self.index}",
                )
        with Vertical(
            id=f"condition-value-field-{self.index}",
            classes="condition-value",
        ):
            yield Label(
                "Comparison value",
                classes="form-label",
                id=f"condition-value-label-{self.index}",
            )
            yield Select(
                [
                    (f"{path} (trusted context)", path)
                    for path in self.trusted_paths
                ],
                prompt="Choose the authoritative runtime field",
                id=f"condition-right-path-{self.index}",
            )
            yield Input(
                placeholder="Enter a value; separate list items with commas",
                id=f"condition-right-literal-{self.index}",
            )


class RuleManagerScreen(CompletionModalScreen):
    MAX_CONDITIONS = 8

    def __init__(
        self,
        policy_path: Path,
        operand_paths: list[str],
        trusted_paths: list[str],
        operand_types: dict[str, str],
        completion: Callable[[str | None], None],
    ) -> None:
        super().__init__(completion)
        self.policy_path = policy_path
        self.policy = load_policy(policy_path)
        self.operand_paths = operand_paths
        self.trusted_paths = trusted_paths
        self.operand_types = operand_types
        self.current_rule_id: str | None = (
            self.policy.rules[0].id if self.policy.rules else None
        )
        self.active_conditions = 1

    def compose(self) -> ComposeResult:
        rule_options = [("Create a new rule", "__new__")] + [
            (f"{rule.id} -> {rule.decision.upper()}", rule.id)
            for rule in self.policy.rules
        ]
        selected = self.current_rule_id or "__new__"
        with Container(id="rule-manager-dialog"):
            yield Label(
                f"Manage rules: {self.policy.tool}",
                classes="dialog-title",
            )
            yield Static(
                "Build rules from discovered action arguments and runtime-provided "
                "trusted context. Use matching fields with the same business meaning; "
                "do not infer a relationship merely because two fields are available.",
                classes="dialog-message",
            )
            with Horizontal(id="rule-editor-body"):
                with VerticalScroll(id="rule-details"):
                    yield Label("Rule details", classes="section-title")
                    yield Label("Rule to edit", classes="form-label")
                    yield Select(
                        rule_options,
                        value=selected,
                        allow_blank=False,
                        id="rule-choice",
                    )
                    yield Static(
                        "An internal rule ID is generated automatically when "
                        "you save a new rule.",
                        classes="field-help",
                        id="rule-id-help",
                    )
                    yield Label("Decision", classes="form-label")
                    yield Select(
                        [
                            ("Allow", "allow"),
                            ("Deny", "deny"),
                            ("Warn", "warn"),
                            ("Escalate", "escalate"),
                        ],
                        value="allow",
                        allow_blank=False,
                        id="rule-decision",
                    )
                    yield Label(
                        "How multiple conditions combine",
                        classes="form-label",
                    )
                    yield Select(
                        [
                            ("All conditions must match", "all"),
                            ("Any condition may match", "any"),
                        ],
                        value="all",
                        allow_blank=False,
                        id="rule-match-mode",
                    )
                    yield Label(
                        "Business justification",
                        classes="form-label",
                    )
                    yield Input(
                        placeholder="Explain why this decision is authorized",
                        id="rule-reason",
                    )
                with Vertical(id="conditions-panel"):
                    yield Label("Conditions", classes="section-title")
                    yield Static(
                        "Requested arguments come from the agent. Trusted context "
                        "comes from the application runtime.",
                        classes="field-help",
                    )
                    with VerticalScroll(id="condition-list"):
                        for index in range(self.MAX_CONDITIONS):
                            yield RuleConditionRow(
                                index,
                                self.operand_paths,
                                self.trusted_paths,
                            )
            with Horizontal(classes="rule-secondary-actions"):
                yield Button(
                    "Add condition",
                    id="add-condition",
                    variant="primary",
                )
                yield Button(
                    "Delete rule",
                    id="delete-rule",
                    variant="error",
                )
                yield Button("Advanced YAML", id="advanced-yaml")
            yield Static("", id="rule-error")
            yield Static("", id="delete-confirmation")
            with Horizontal(id="delete-actions"):
                yield Button("Keep rule", id="cancel-delete")
                yield Button(
                    "Confirm delete",
                    id="confirm-delete",
                    variant="error",
                )
            with Horizontal(id="rule-dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save rule", id="save-rule", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#delete-actions", Horizontal).display = False
        self._set_responsive_layout(self.size.width)
        self._load_selected_rule(self.current_rule_id)

    def on_resize(self, event: events.Resize) -> None:
        self._set_responsive_layout(event.size.width)

    def _set_responsive_layout(self, width: int) -> None:
        if width < 100:
            self.add_class("narrow")
        else:
            self.remove_class("narrow")

    def _row(self, index: int) -> RuleConditionRow:
        return self.query_one(f"#condition-row-{index}", RuleConditionRow)

    def _set_select(self, selector: str, value: str) -> None:
        select = self.query_one(selector, Select)
        select.value = value

    def _clear_row(self, index: int) -> None:
        self.query_one(f"#condition-left-{index}", Select).clear()
        self._set_select(f"#condition-operator-{index}", "equals")
        self._set_select(f"#condition-right-kind-{index}", "path")
        self.query_one(f"#condition-right-path-{index}", Select).clear()
        self.query_one(f"#condition-right-literal-{index}", Input).value = ""

    def _leaf_conditions(self, rule: PolicyRule) -> tuple[str, list[Condition]]:
        condition = rule.condition
        if condition.operator in {"all", "any"}:
            if any(
                child.operator in {"all", "any", "not"}
                for child in condition.conditions
            ):
                raise ValueError(
                    "This rule contains nested condition groups. Use Advanced YAML "
                    "to edit it without changing its meaning."
                )
            if len(condition.conditions) > self.MAX_CONDITIONS:
                raise ValueError(
                    f"This rule contains {len(condition.conditions)} conditions. "
                    f"Guided editing supports up to {self.MAX_CONDITIONS}; use "
                    "Advanced YAML to edit it without truncating its meaning."
                )
            return condition.operator, list(condition.conditions)
        if condition.operator == "not":
            raise ValueError(
                "This rule uses a nested NOT expression. Use Advanced YAML to edit "
                "it without changing its meaning."
            )
        return "all", [condition]

    def _load_selected_rule(self, rule_id: str | None) -> None:
        error = self.query_one("#rule-error", Static)
        error.update("")
        self.query_one("#delete-confirmation", Static).update("")
        self.query_one("#delete-actions", Horizontal).display = False
        self.query_one("#save-rule", Button).disabled = False
        for index in range(self.MAX_CONDITIONS):
            self._clear_row(index)
            self._row(index).display = index == 0
        self.active_conditions = 1
        self.current_rule_id = rule_id
        self.query_one("#delete-rule", Button).disabled = rule_id is None
        if rule_id is None:
            self._set_select("#rule-decision", "allow")
            self._set_select("#rule-match-mode", "all")
            self.query_one("#rule-reason", Input).value = ""
            return
        rule = next(item for item in self.policy.rules if item.id == rule_id)
        self._set_select("#rule-decision", rule.decision)
        self.query_one("#rule-reason", Input).value = rule.reason
        try:
            match_mode, conditions = self._leaf_conditions(rule)
        except ValueError as exc:
            error.update(str(exc))
            self.query_one("#save-rule", Button).disabled = True
            return
        self.query_one("#save-rule", Button).disabled = False
        self._set_select("#rule-match-mode", match_mode)
        self.active_conditions = min(len(conditions), self.MAX_CONDITIONS)
        for index, condition in enumerate(conditions[: self.MAX_CONDITIONS]):
            self._row(index).display = True
            if condition.left is not None and condition.left.path is not None:
                self._set_select(
                    f"#condition-left-{index}",
                    condition.left.path,
                )
            self._set_select(
                f"#condition-operator-{index}",
                condition.operator,
            )
            if condition.operator in {"in", "not_in"}:
                self._set_select(
                    f"#condition-right-kind-{index}",
                    "literal",
                )
                self.query_one(
                    f"#condition-right-literal-{index}",
                    Input,
                ).value = ", ".join(str(value) for value in condition.values)
            elif condition.right is not None:
                if condition.right.path is not None:
                    self._set_select(
                        f"#condition-right-kind-{index}",
                        "path",
                    )
                    self._set_select(
                        f"#condition-right-path-{index}",
                        condition.right.path,
                    )
                else:
                    self._set_select(
                        f"#condition-right-kind-{index}",
                        "literal",
                    )
                    self.query_one(
                        f"#condition-right-literal-{index}",
                        Input,
                    ).value = yaml.safe_dump(
                        condition.right.literal,
                        default_flow_style=True,
                    ).strip()
        self._refresh_condition_fields()

    def _refresh_condition_fields(self) -> None:
        for index in range(self.active_conditions):
            operator = str(
                self.query_one(
                    f"#condition-operator-{index}",
                    Select,
                ).value
            )
            right_kind = str(
                self.query_one(
                    f"#condition-right-kind-{index}",
                    Select,
                ).value
            )
            uses_values = operator in {"in", "not_in"}
            uses_right = operator != "exists"
            self.query_one(
                f"#condition-kind-field-{index}",
                Vertical,
            ).display = uses_right and not uses_values
            self.query_one(
                f"#condition-value-field-{index}",
                Vertical,
            ).display = uses_right
            self.query_one(
                f"#condition-right-path-{index}",
                Select,
            ).display = uses_right and not uses_values and right_kind == "path"
            self.query_one(
                f"#condition-right-literal-{index}",
                Input,
            ).display = uses_values or (uses_right and right_kind == "literal")
            value_label = self.query_one(
                f"#condition-value-label-{index}",
                Label,
            )
            if uses_values:
                value_label.update("Comparison values")
            elif right_kind == "literal":
                value_label.update("Fixed comparison value")
            else:
                value_label.update("Trusted context field")
            if uses_values:
                self.call_after_refresh(
                    self._show_condition_value,
                    index,
                )

    def _show_condition_value(self, index: int) -> None:
        self.query_one(
            f"#condition-right-literal-{index}",
            Input,
        ).scroll_visible(animate=False)

    @on(Select.Changed)
    def selection_changed(self, event: Select.Changed) -> None:
        if event.select.id == "rule-choice":
            value = event.value
            if value is Select.BLANK:
                return
            self._load_selected_rule(
                None if value == "__new__" else str(value)
            )
            return
        if event.select.id and (
            event.select.id.startswith("condition-operator-")
            or event.select.id.startswith("condition-right-kind-")
        ):
            self._refresh_condition_fields()

    @on(Button.Pressed, "#add-condition")
    def add_condition(self) -> None:
        if self.active_conditions >= self.MAX_CONDITIONS:
            self.query_one("#rule-error", Static).update(
                f"Guided editing supports up to {self.MAX_CONDITIONS} conditions "
                "per rule. Use Advanced YAML for a larger expression."
            )
            return
        self._row(self.active_conditions).display = True
        self.active_conditions += 1
        self._refresh_condition_fields()

    @on(Button.Pressed)
    def remove_condition(self, event: Button.Pressed) -> None:
        if not event.button.id or not event.button.id.startswith(
            "remove-condition-"
        ):
            return
        index = int(event.button.id.rsplit("-", 1)[1])
        if self.active_conditions == 1:
            self.query_one("#rule-error", Static).update(
                "A rule must contain at least one condition."
            )
            return
        for current in range(index, self.active_conditions - 1):
            self._copy_row(current + 1, current)
        self.active_conditions -= 1
        self._clear_row(self.active_conditions)
        self._row(self.active_conditions).display = False
        self._refresh_condition_fields()

    def _copy_row(self, source: int, target: int) -> None:
        for field in ("left", "operator", "right-kind", "right-path"):
            source_widget = self.query_one(
                f"#condition-{field}-{source}",
                Select,
            )
            target_widget = self.query_one(
                f"#condition-{field}-{target}",
                Select,
            )
            if source_widget.value is Select.BLANK:
                target_widget.clear()
            else:
                target_widget.value = source_widget.value
        self.query_one(
            f"#condition-right-literal-{target}",
            Input,
        ).value = self.query_one(
            f"#condition-right-literal-{source}",
            Input,
        ).value

    def _literal(self, value: str) -> Any:
        if not value.strip():
            raise ValueError("enter a fixed comparison value")
        parsed = yaml.safe_load(value)
        if parsed is None:
            raise ValueError("the fixed comparison value cannot be empty")
        return parsed

    def _value_matches_type(self, value: Any, expected: str) -> bool:
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
            )
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "array":
            return isinstance(value, list)
        if expected == "object":
            return isinstance(value, dict)
        return True

    def _type_name(self, expected: str) -> str:
        return {
            "string": "text",
            "integer": "a whole number",
            "number": "a number",
            "boolean": "true or false",
            "array": "a list",
            "object": "an object",
        }.get(expected, expected)

    def _validate_literal_type(
        self,
        index: int,
        left_path: str,
        value: Any,
    ) -> None:
        expected = self.operand_types.get(left_path)
        if expected is None or self._value_matches_type(value, expected):
            return
        guidance = ""
        if expected == "string":
            guidance = ' Quote numeric-looking text, for example "123".'
        raise ValueError(
            f"Condition {index + 1}: {left_path} expects "
            f"{self._type_name(expected)}.{guidance}"
        )

    def _validate_path_types(
        self,
        index: int,
        left_path: str,
        right_path: str,
    ) -> None:
        left_type = self.operand_types.get(left_path)
        right_type = self.operand_types.get(right_path)
        numeric_types = {"integer", "number"}
        if (
            left_type is None
            or right_type is None
            or left_type == right_type
            or {left_type, right_type} <= numeric_types
        ):
            return
        raise ValueError(
            f"Condition {index + 1}: {left_path} is {left_type}, but "
            f"{right_path} is {right_type}. Compare fields with compatible types."
        )

    def _condition_document(self, index: int) -> dict[str, Any]:
        left = self.query_one(f"#condition-left-{index}", Select).value
        operator = self.query_one(
            f"#condition-operator-{index}",
            Select,
        ).value
        if left is Select.BLANK:
            raise ValueError(f"Condition {index + 1}: choose a field")
        document: dict[str, Any] = {
            "operator": str(operator),
            "left": {"path": str(left)},
        }
        if operator == "exists":
            return document
        literal_input = self.query_one(
            f"#condition-right-literal-{index}",
            Input,
        ).value
        if operator in {"in", "not_in"}:
            values = [
                self._literal(item)
                for item in literal_input.split(",")
                if item.strip()
            ]
            if not values:
                raise ValueError(
                    f"Condition {index + 1}: enter one or more comparison values"
                )
            for value in values:
                self._validate_literal_type(index, str(left), value)
            document["values"] = values
            return document
        right_kind = self.query_one(
            f"#condition-right-kind-{index}",
            Select,
        ).value
        if right_kind == "path":
            right_path = self.query_one(
                f"#condition-right-path-{index}",
                Select,
            ).value
            if right_path is Select.BLANK:
                raise ValueError(
                    f"Condition {index + 1}: choose a trusted comparison field"
                )
            self._validate_path_types(
                index,
                str(left),
                str(right_path),
            )
            document["right"] = {"path": str(right_path)}
        else:
            literal = self._literal(literal_input)
            self._validate_literal_type(index, str(left), literal)
            document["right"] = {"literal": literal}
        return document

    @on(Button.Pressed, "#save-rule")
    def save_rule(self) -> None:
        decision = self.query_one("#rule-decision", Select).value
        reason = self.query_one("#rule-reason", Input).value.strip()
        match_mode = self.query_one("#rule-match-mode", Select).value
        try:
            conditions = [
                self._condition_document(index)
                for index in range(self.active_conditions)
            ]
            condition: dict[str, Any]
            if len(conditions) == 1:
                condition = conditions[0]
            else:
                condition = {
                    "operator": str(match_mode),
                    "conditions": conditions,
                }
            existing_ids = {
                item.id
                for item in self.policy.rules
                if item.id != self.current_rule_id
            }
            rule_id = self.current_rule_id or _generated_rule_id(
                str(decision),
                reason,
                existing_ids,
            )
            rule = PolicyRule.model_validate(
                {
                    "id": rule_id,
                    "decision": str(decision),
                    "reason": reason,
                    "condition": condition,
                }
            )
            rules = list(self.policy.rules)
            if self.current_rule_id is None:
                rules.append(rule)
            else:
                rules = [
                    rule if item.id == self.current_rule_id else item
                    for item in rules
                ]
            updated = CanonicalPolicy.model_validate(
                {
                    **self.policy.model_dump(mode="json"),
                    "rules": [
                        item.model_dump(mode="json")
                        for item in rules
                    ],
                }
            )
            self._persist_policy(updated)
        except (ValueError, OSError, ValidationError) as exc:
            self.query_one("#rule-error", Static).update(
                _friendly_error("Could not save this rule", exc)
            )
            return
        self.complete("saved")

    def _persist_policy(self, policy: CanonicalPolicy) -> None:
        original = self.policy_path.read_text(encoding="utf-8")
        try:
            self.policy_path.write_text(
                yaml.safe_dump(
                    policy.model_dump(mode="json"),
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            load_policy(self.policy_path)
        except (OSError, ValueError, ValidationError):
            self.policy_path.write_text(original, encoding="utf-8")
            raise

    @on(Button.Pressed, "#delete-rule")
    def request_delete(self) -> None:
        if self.current_rule_id is None:
            return
        self.query_one("#delete-confirmation", Static).update(
            f"Delete rule {self.current_rule_id!r}? The policy will fall back to "
            "its remaining rules and default decision."
        )
        self.query_one("#delete-actions", Horizontal).display = True

    @on(Button.Pressed, "#cancel-delete")
    def cancel_delete(self) -> None:
        self.query_one("#delete-confirmation", Static).update("")
        self.query_one("#delete-actions", Horizontal).display = False

    @on(Button.Pressed, "#confirm-delete")
    def confirm_delete(self) -> None:
        if self.current_rule_id is None:
            return
        updated = CanonicalPolicy.model_validate(
            {
                **self.policy.model_dump(mode="json"),
                "rules": [
                    rule.model_dump(mode="json")
                    for rule in self.policy.rules
                    if rule.id != self.current_rule_id
                ],
            }
        )
        try:
            self._persist_policy(updated)
        except (ValueError, OSError, ValidationError) as exc:
            self.query_one("#rule-error", Static).update(str(exc))
            return
        self.complete("saved")

    @on(Button.Pressed, "#advanced-yaml")
    def advanced_yaml(self) -> None:
        self.complete("advanced")

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(None)


class ApprovalScreen(CompletionModalScreen):
    def __init__(
        self,
        workspace: Path,
        packet: dict[str, Any],
        tool_name: str | None,
        completion: Callable[[dict[str, Any] | None], None],
    ) -> None:
        super().__init__(completion)
        self.workspace = workspace
        self.packet = packet
        self.tool_name = tool_name
        self.policy_count = len(packet["policies"])
        self.findings = sorted(
            {
                str(finding)
                for policy in packet["policies"]
                for finding in policy["blocking_findings"]
            }
        )

    def compose(self) -> ComposeResult:
        scope = (
            self.tool_name
            if self.tool_name is not None
            else f"all {self.policy_count} policies"
        )
        with Container(id="approval-dialog"):
            yield Label(f"Approve {scope}", classes="dialog-title")
            yield Static(
                "Approval is bound to the exact selected policies, tests, source, "
                "context, findings, and target adapters.",
                classes="dialog-message",
            )
            yield Static(
                f"Snapshot: {self.packet['confirmation_digest']}",
                classes="digest",
                id="approval-digest",
            )
            with Collapsible(
                title="Approval evidence packet",
                collapsed=True,
                id="approval-evidence",
            ):
                yield Static(
                    _approval_packet_review(self.packet),
                    classes="section-content",
                    id="approval-evidence-content",
                )
            yield Label("Reviewer identity *", classes="form-label")
            yield Input(
                placeholder="Example: alex@example.com",
                id="reviewer",
            )
            yield Label(
                "Reviewer role or team",
                classes="form-label",
            )
            yield Input(
                placeholder="Required when dispositioning a finding",
                id="reviewer-role",
            )
            yield Label(
                "Approval rationale *",
                classes="form-label",
            )
            yield Input(
                placeholder="Explain what you reviewed and why approval is justified",
                id="rationale",
            )
            yield Static(
                "* Required. Rationale must contain at least 12 characters.",
                classes="field-help",
            )
            for index, finding in enumerate(self.findings):
                with Collapsible(title=f"Finding: {finding}", collapsed=False):
                    yield Label("Disposition *", classes="form-label")
                    yield Select(
                        [
                            ("False positive", "false_positive"),
                            ("Accept temporary risk", "accepted_risk"),
                        ],
                        prompt="Choose a disposition",
                        id=f"disposition-{index}",
                    )
                    yield Label(
                        "Disposition rationale *",
                        classes="form-label",
                    )
                    yield Input(
                        placeholder="Explain why this treatment is justified",
                        id=f"finding-rationale-{index}",
                    )
                    yield Label(
                        "Evidence references *",
                        classes="form-label",
                    )
                    yield Input(
                        placeholder=(
                            "Comma-separated links, tickets, or source references"
                        ),
                        id=f"finding-evidence-{index}",
                    )
                    with Vertical(id=f"accepted-risk-fields-{index}"):
                        yield Label(
                            "Risk expiry date *",
                            classes="form-label",
                        )
                        yield Input(
                            placeholder="YYYY-MM-DD or MM/DD/YYYY",
                            id=f"finding-expiry-{index}",
                        )
                        yield Static(
                            "A date is interpreted as the end of that day in UTC. "
                            "A full timestamp is also accepted.",
                            classes="field-help",
                        )
                        yield Label(
                            "Compensating controls *",
                            classes="form-label",
                        )
                        yield Input(
                            placeholder="Comma-separated safeguards while risk is open",
                            id=f"finding-controls-{index}",
                        )
            acknowledgements = self.packet["required_semantic_acknowledgements"]
            for index, acknowledgement in enumerate(acknowledgements):
                yield Checkbox(
                    f"Acknowledge fail-closed target difference: {acknowledgement}",
                    id=f"ack-{index}",
                )
            yield Checkbox(
                "I reviewed this exact policy, its mappings, tests, and evidence.",
                id="confirm-snapshot",
            )
            yield Static("", id="approval-error")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    (
                        "Approve selected policy"
                        if self.tool_name is not None
                        else f"Approve all {self.policy_count} policies"
                    ),
                    id="confirm-approval",
                    variant="success",
                )

    def on_mount(self) -> None:
        for index in range(len(self.findings)):
            self.query_one(
                f"#accepted-risk-fields-{index}",
                Vertical,
            ).display = False

    @on(Select.Changed)
    def disposition_changed(self, event: Select.Changed) -> None:
        if not event.select.id or not event.select.id.startswith(
            "disposition-"
        ):
            return
        index = int(event.select.id.rsplit("-", 1)[1])
        self.query_one(
            f"#accepted-risk-fields-{index}",
            Vertical,
        ).display = event.value == "accepted_risk"

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(None)

    @on(Button.Pressed, "#confirm-approval")
    def approve(self) -> None:
        reviewer = self.query_one("#reviewer", Input).value.strip()
        role = self.query_one("#reviewer-role", Input).value.strip()
        rationale = self.query_one("#rationale", Input).value.strip()
        confirmed = self.query_one("#confirm-snapshot", Checkbox).value
        if not reviewer or len(rationale) < 12 or not confirmed:
            self.query_one("#approval-error", Static).update(
                "Reviewer, a rationale of at least 12 characters, and the "
                "review confirmation are required."
            )
            return
        dispositions: list[FindingDisposition] = []
        try:
            for index, finding in enumerate(self.findings):
                disposition = self.query_one(
                    f"#disposition-{index}",
                    Select,
                ).value
                if disposition is Select.BLANK:
                    raise ValueError(f"{finding}: choose a disposition")
                evidence = _split_csv(
                    self.query_one(f"#finding-evidence-{index}", Input).value
                )
                values: dict[str, Any] = {
                    "finding_id": finding,
                    "disposition": str(disposition),
                    "rationale": self.query_one(
                        f"#finding-rationale-{index}",
                        Input,
                    ).value.strip(),
                    "evidence": evidence,
                }
                if not evidence:
                    raise ValueError(
                        f"{finding}: add at least one evidence reference"
                    )
                if disposition == "accepted_risk":
                    controls = _split_csv(
                        self.query_one(
                            f"#finding-controls-{index}",
                            Input,
                        ).value
                    )
                    if not controls:
                        raise ValueError(
                            f"{finding}: accepted risk requires at least one "
                            "compensating control"
                        )
                    expiry = _normalize_expiry(
                        self.query_one(
                            f"#finding-expiry-{index}",
                            Input,
                        ).value
                    )
                    if datetime.fromisoformat(expiry) <= datetime.now(UTC):
                        raise ValueError(
                            f"{finding}: risk expiry must be a future date"
                        )
                    values["expires_at"] = expiry
                    values["compensating_controls"] = controls
                dispositions.append(FindingDisposition.model_validate(values))
        except (ValueError, ValidationError) as exc:
            self.query_one("#approval-error", Static).update(
                _friendly_error("Could not approve this policy", exc)
            )
            return
        if dispositions and not role:
            self.query_one("#approval-error", Static).update(
                "Reviewer role or team is required when dispositioning findings."
            )
            return
        acknowledgements = []
        required = self.packet["required_semantic_acknowledgements"]
        for index, acknowledgement in enumerate(required):
            if not self.query_one(f"#ack-{index}", Checkbox).value:
                self.query_one("#approval-error", Static).update(
                    "Every target semantic difference must be acknowledged."
                )
                return
            acknowledgements.append(str(acknowledgement))
        current_packet = build_approval_packet(
            self.workspace,
            tool_name=self.tool_name,
            finding_dispositions=dispositions,
            semantic_acknowledgements=acknowledgements,
        )
        current_digest = str(current_packet["confirmation_digest"])
        if current_digest != self.packet["confirmation_digest"]:
            self.packet = current_packet
            self.query_one("#approval-digest", Static).update(
                f"Snapshot: {current_digest}"
            )
            self.query_one("#approval-evidence-content", Static).update(
                _approval_packet_review(current_packet)
            )
            self.query_one("#confirm-snapshot", Checkbox).value = False
            self.query_one("#approval-error", Static).update(
                "The dispositions or acknowledgements changed the approval "
                "snapshot. Review the updated digest, confirm it, and approve "
                "again."
            )
            return
        self.complete(
            {
                "reviewer": reviewer,
                "reviewer_role": role or None,
                "rationale": rationale,
                "finding_dispositions": dispositions,
                "semantic_acknowledgements": acknowledgements,
                "approval_packet_digest": current_digest,
            }
        )


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _normalize_expiry(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError(
            "Enter a risk expiry date, for example 2026-10-31."
        )
    for date_format in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            parsed = datetime.strptime(raw, date_format).replace(
                hour=23,
                minute=59,
                second=59,
                tzinfo=UTC,
            )
            return parsed.isoformat()
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "Enter the expiry as YYYY-MM-DD or MM/DD/YYYY, for example "
            "2026-10-31."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def _friendly_error(title: str, error: Exception) -> str:
    if not isinstance(error, ValidationError):
        return f"{title}:\n- {error}"
    messages: list[str] = []
    for item in error.errors(include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        field = str(item["loc"][-1]) if item["loc"] else ""
        if field == "id":
            message = (
                "Rule ID must start with a lowercase letter and contain only "
                "lowercase letters, numbers, or hyphens."
            )
        elif field == "reason":
            message = "Enter a business justification for this rule."
        elif field == "rationale":
            message = "Enter a rationale of at least 12 characters."
        elif field == "expires_at":
            message = (
                "Enter the expiry as YYYY-MM-DD or MM/DD/YYYY."
            )
        else:
            message = str(item["msg"])
            if location:
                message = f"{location}: {message}"
        if message not in messages:
            messages.append(message)
    return title + ":\n" + "\n".join(f"- {message}" for message in messages)


class CompileScreen(CompletionModalScreen):
    def __init__(
        self,
        completion: Callable[[dict[str, bool] | None], None],
    ) -> None:
        super().__init__(completion)

    def compose(self) -> ComposeResult:
        with Container(id="confirm-dialog"):
            yield Label("Compile publication bundle", classes="dialog-title")
            yield Static(
                "Compilation creates and promotes an immutable bundle inside "
                "this local workspace. It does not deploy to a remote service.",
                classes="dialog-message",
            )
            yield Checkbox(
                "Require declared validation assurance for every target",
                value=True,
                id="require-validated",
            )
            yield Checkbox(
                "Require exact target semantics",
                value=False,
                id="require-exact",
            )
            yield Checkbox(
                "Allow dirty product provenance for this development bundle",
                value=False,
                id="allow-dirty",
            )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Compile local bundle",
                    id="confirm-compile",
                    variant="success",
                )

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(None)

    @on(Button.Pressed, "#confirm-compile")
    def compile_bundle(self) -> None:
        self.complete(
            {
                "require_validated": self.query_one(
                    "#require-validated",
                    Checkbox,
                ).value,
                "require_exact_semantics": self.query_one(
                    "#require-exact",
                    Checkbox,
                ).value,
                "allow_dirty_product": self.query_one(
                    "#allow-dirty",
                    Checkbox,
                ).value,
            }
        )


class ExportScreen(CompletionModalScreen):
    def __init__(
        self,
        workspace: Path,
        tool_name: str,
        targets: list[str],
        completion: Callable[[dict[str, Any] | None], None],
    ) -> None:
        super().__init__(completion)
        self.workspace = workspace
        self.tool_name = tool_name
        self.targets = targets
        self.default_target = "acs" if "acs" in targets else targets[0]
        self.default_path = self._default_path(self.default_target)

    def _default_path(self, target: str) -> str:
        target_name = (
            "microsoft-agent-governance-toolkit-acs"
            if target == "acs"
            else target
        )
        return str(
            self.workspace
            / "exports"
            / f"{self.tool_name}-{target_name}.zip"
        )

    def compose(self) -> ComposeResult:
        with Container(id="confirm-dialog"):
            yield Label("Export policy package", classes="dialog-title")
            yield Static(
                "Export the selected policy from the verified, immutable "
                "publication bundle. The ZIP contains the engine-ready package.",
                classes="dialog-message",
            )
            yield Label("Target engine", classes="form-label")
            yield Select(
                [
                    (TARGET_LABELS.get(target, target), target)
                    for target in self.targets
                ],
                value=self.default_target,
                allow_blank=False,
                id="export-target",
            )
            yield Label("Destination ZIP", classes="form-label")
            yield Input(value=self.default_path, id="export-destination")
            yield Checkbox(
                "Replace the destination if it already exists",
                value=False,
                id="export-overwrite",
            )
            yield Static("", id="export-error")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Export ZIP",
                    id="confirm-export",
                    variant="success",
                )

    @on(Select.Changed, "#export-target")
    def target_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        destination = self.query_one("#export-destination", Input)
        if destination.value == self.default_path:
            self.default_path = self._default_path(str(event.value))
            destination.value = self.default_path

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.complete(None)

    @on(Button.Pressed, "#confirm-export")
    def export(self) -> None:
        target = self.query_one("#export-target", Select).value
        destination = self.query_one("#export-destination", Input).value.strip()
        if target is Select.BLANK or not destination:
            self.query_one("#export-error", Static).update(
                "Choose a target engine and destination ZIP."
            )
            return
        self.complete(
            {
                "target": str(target),
                "destination": Path(destination),
                "overwrite": self.query_one(
                    "#export-overwrite",
                    Checkbox,
                ).value,
            }
        )


class PolicyWorkbenchApp(App[None]):
    TITLE = "Agent Policy Author Workbench"
    SUB_TITLE = "Review, map, test, approve, and publish from one place"

    CSS = """
    Screen {
        background: $surface;
    }
    #workspace-summary {
        height: 4;
        padding: 0 2;
        background: $panel;
        border-bottom: solid $primary;
    }
    #main {
        height: 1fr;
    }
    #policy-nav {
        width: 28;
        min-width: 22;
        border-right: solid $primary-background;
        background: $panel;
    }
    #policy-nav-title {
        padding: 1 1 0 1;
        text-style: bold;
        color: $text-muted;
    }
    #policy-list {
        height: 1fr;
    }
    ListItem {
        height: auto;
        min-height: 3;
        padding: 0 1;
    }
    #detail-scroll {
        width: 1fr;
        padding: 1 2 2 2;
    }
    #empty-detail {
        margin: 3;
        color: $text-muted;
    }
    #actions {
        height: 3;
        padding: 0 1;
        background: $panel;
        border-top: solid $primary-background;
    }
    .action-row {
        height: 1;
        align-horizontal: center;
        align-vertical: middle;
    }
    #actions Button {
        width: auto;
        min-width: 0;
        height: 1;
        margin: 0 1 0 0;
        padding: 0 1;
        border: none;
    }
    .policy-heading {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    .policy-subheading {
        color: $text-muted;
        margin-bottom: 1;
    }
    Collapsible {
        margin: 0 0 1 0;
        border: round $primary-background;
    }
    CollapsibleTitle {
        padding: 0 1;
    }
    .section-content {
        padding: 1 2;
    }
    .warning {
        color: $warning;
    }
    .error {
        color: $error;
    }
    .success {
        color: $success;
    }
    ModalScreen {
        align: center middle;
        background: $background 70%;
    }
    #message-dialog, #confirm-dialog {
        width: 70%;
        max-width: 100;
        height: auto;
        padding: 1 2;
        border: round $primary;
        background: $surface;
    }
    #editor-dialog, #approval-dialog, #reconciliation-dialog {
        width: 90%;
        height: 90%;
        padding: 1 2;
        border: round $primary;
        background: $surface;
        overflow-y: auto;
    }
    #editor-dialog, #reconciliation-dialog, #approval-dialog,
    #rule-manager-dialog {
        layout: vertical;
    }
    #reconciliation-body {
        height: 1fr;
    }
    #confirm-dialog Checkbox, #reconciliation-dialog Checkbox {
        width: 1fr;
        height: auto;
    }
    #confirm-dialog Input, #confirm-dialog Select {
        width: 100%;
    }
    #rule-manager-dialog {
        width: 98%;
        height: 100%;
        padding: 0 1;
        border: solid $primary;
        background: $surface;
    }
    #approval-dialog {
        width: 94%;
        height: 94%;
        padding: 1 3;
        border: solid $primary;
        background: $surface;
    }
    #approval-dialog .dialog-buttons {
        dock: bottom;
    }
    #approval-dialog Input, #approval-dialog Select {
        width: 100%;
    }
    #approval-dialog Collapsible {
        border: solid $primary-background;
    }
    #rule-editor-body {
        height: 1fr;
        min-height: 6;
    }
    #rule-details {
        width: 34%;
        min-width: 28;
        padding: 1 2;
        margin-right: 1;
        border: solid $primary-background;
        background: $panel;
    }
    #conditions-panel {
        width: 1fr;
        padding: 1 2 0 2;
        border: solid $primary-background;
    }
    #rule-details Input, #rule-details Select {
        width: 100%;
    }
    .section-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    .form-label {
        text-style: bold;
        color: $text;
        margin-top: 1;
    }
    .field-help {
        color: $text-muted;
        margin-bottom: 1;
    }
    .condition-fields, .rule-secondary-actions {
        height: auto;
        margin-bottom: 1;
    }
    #condition-list {
        height: 1fr;
        min-height: 10;
        padding: 0 1 1 0;
    }
    .condition-row {
        height: auto;
        min-height: 12;
        padding: 1 2;
        border: solid $primary-background;
        background: $panel;
        margin-bottom: 1;
    }
    .condition-heading {
        height: 2;
        align-vertical: middle;
    }
    .condition-title {
        text-style: bold;
        color: $primary;
        width: 1fr;
    }
    .remove-condition {
        width: 12;
    }
    .condition-field {
        height: auto;
        margin-right: 1;
    }
    .condition-left {
        width: 42%;
    }
    .condition-operator {
        width: 28%;
    }
    .condition-kind {
        width: 30%;
        margin-right: 0;
    }
    .condition-field Select, .condition-value Select,
    .condition-value Input {
        width: 100%;
    }
    .condition-value {
        height: auto;
    }
    .narrow #rule-editor-body {
        layout: vertical;
        height: 1fr;
    }
    .narrow #rule-details, .narrow #conditions-panel {
        width: 100%;
        min-width: 0;
        height: 1fr;
        margin-right: 0;
        margin-bottom: 1;
    }
    .narrow #condition-list {
        height: auto;
        min-height: 24;
    }
    .narrow .condition-fields {
        layout: vertical;
    }
    .narrow .condition-left,
    .narrow .condition-operator,
    .narrow .condition-kind {
        width: 100%;
        margin-right: 0;
    }
    .rule-secondary-actions Button {
        margin-right: 1;
    }
    ModalScreen Button {
        width: auto;
        min-width: 0;
        height: 1;
        padding: 0 2;
        border: none;
    }
    #delete-actions {
        height: auto;
        align-horizontal: right;
        margin-bottom: 1;
    }
    #delete-actions Button {
        margin-left: 1;
    }
    #rule-dialog-buttons {
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }
    #rule-dialog-buttons Button {
        margin-left: 1;
    }
    #rule-error, #delete-confirmation {
        color: $error;
        height: auto;
        margin: 0;
    }
    #rule-error, #approval-error {
        padding: 0 1;
        background: $error 10%;
    }
    #yaml-editor {
        height: 1fr;
        min-height: 6;
        margin: 1 0;
        border: round $primary-background;
    }
    .dialog-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    .dialog-message {
        margin-bottom: 1;
    }
    .dialog-error, #editor-error, #approval-error, #reconciliation-error,
    #export-error {
        color: $error;
        margin: 1 0;
    }
    .dialog-buttons {
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }
    .dialog-buttons Button {
        margin-left: 1;
    }
    .path, .digest {
        color: $text-muted;
    }
    .narrow #policy-nav {
        width: 22;
        min-width: 18;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "reload", "Reload"),
        ("t", "run_tests", "Run tests"),
        ("e", "edit_policy", "Manage rules"),
        ("a", "approve_policy", "Approve"),
        ("s", "sync_source", "Sync source"),
        ("c", "compile_bundle", "Compile"),
        ("v", "verify_bundle", "Verify"),
        ("x", "export_policy", "Export"),
    ]

    def __init__(
        self,
        workspace: Path,
        report: dict[str, Any],
        *,
        run_tests: bool,
    ) -> None:
        super().__init__()
        self.workspace = workspace.resolve()
        self.report = report
        self.run_tests_on_reload = run_tests
        self.selected_tool: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="workspace-summary")
        with Horizontal(id="main"):
            with Vertical(id="policy-nav"):
                yield Label("POLICIES", id="policy-nav-title")
                yield ListView(id="policy-list")
            with VerticalScroll(id="detail-scroll"):
                yield Static(
                    "Select a policy to review its mappings, rules, tests, "
                    "findings, and raw YAML.",
                    id="empty-detail",
                )
                yield Static("", id="policy-heading", classes="policy-heading")
                yield Static(
                    "",
                    id="policy-subheading",
                    classes="policy-subheading",
                )
                with Collapsible(
                    title="1. Policy properties and source mapping",
                    collapsed=False,
                    id="property-section",
                ):
                    yield Static(id="property-content", classes="section-content")
                with Collapsible(
                    title="2. Decision rules and condition mappings",
                    collapsed=False,
                    id="rules-section",
                ):
                    yield Static(id="rules-content", classes="section-content")
                with Collapsible(
                    title="3. Policy authoring help",
                    collapsed=True,
                    id="authoring-section",
                ):
                    yield Static(id="authoring-content", classes="section-content")
                with Collapsible(
                    title="4. Findings and review questions",
                    collapsed=True,
                    id="findings-section",
                ):
                    yield Static(id="findings-content", classes="section-content")
                with Collapsible(
                    title="5. Behavioral tests",
                    collapsed=True,
                    id="tests-section",
                ):
                    yield Static(id="tests-content", classes="section-content")
                with Collapsible(
                    title="6. Raw policy YAML",
                    collapsed=True,
                    id="raw-policy-section",
                ):
                    yield Static(id="raw-policy-content", classes="section-content")
        with Vertical(id="actions"):
            with Horizontal(classes="action-row five-actions"):
                yield Button("Reload", id="reload")
                yield Button("Manage rules", id="edit-policy", variant="primary")
                yield Button("Edit tests", id="edit-tests")
                yield Button("Context contract", id="edit-context")
                yield Button("Run tests", id="run-tests", variant="primary")
            with Horizontal(classes="action-row six-actions"):
                yield Button("Approve", id="approve", variant="success")
                yield Button("Approve all", id="approve-all", variant="success")
                yield Button("Sync", id="sync", variant="warning")
                yield Button("Compile", id="compile", variant="success")
                yield Button("Verify", id="verify")
                yield Button("Export", id="export", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self._set_responsive_layout(self.size.width)
        self._render_report(select_first=True)

    def on_resize(self, event: events.Resize) -> None:
        self._set_responsive_layout(event.size.width)

    def _set_responsive_layout(self, width: int) -> None:
        if width < 100:
            self.add_class("narrow")
        else:
            self.remove_class("narrow")

    def _main_query_one(
        self,
        selector: str,
        widget_type: type[Widget],
    ) -> Any:
        return self.screen_stack[0].query_one(selector, widget_type)

    def _render_report(self, *, select_first: bool = False) -> None:
        summary = self.report["summary"]
        readiness = str(self.report["readiness"])
        status = Text()
        status.append("READINESS  ", style="bold")
        status.append(readiness.replace("_", " ").upper(), _status_color(readiness))
        status.append(
            f"\n{summary['approved']}/{summary['policies']} approved"
            f"  |  {summary['blocking_findings']} unresolved findings"
            f"  |  tests {self.report['tests']['status'].replace('_', ' ')}"
            f"  |  warnings {len(self.report.get('warnings', []))}",
            "bright_black",
        )
        status.append(f"\n{self.report['resolved_source']}", "bright_black")
        self._main_query_one("#workspace-summary", Static).update(status)
        policy_list = self._main_query_one("#policy-list", ListView)
        policy_list.clear()
        for policy in self.report["policies"]:
            policy_list.append(
                ListItem(
                    Static(_policy_list_label(policy)),
                    name=str(policy["tool"]),
                )
            )
        self._main_query_one("#sync", Button).disabled = (
            readiness != "needs_reconciliation"
        )
        self._main_query_one("#compile", Button).disabled = readiness != "passed"
        self._main_query_one("#export", Button).disabled = (
            readiness != "passed"
            or not (self.workspace / "generated" / "current.json").is_file()
        )
        has_policy = bool(self.report["policies"])
        for button_id in ("#edit-policy", "#edit-tests"):
            self._main_query_one(button_id, Button).disabled = not has_policy
        approve_all = self._main_query_one("#approve-all", Button)
        approve_all.disabled = (
            not has_policy
            or any(
                not bool(item.get("approval_eligible"))
                for item in self.report["policies"]
            )
        )
        selected_item = self._selected_report()
        if selected_item is None and self.report["policies"]:
            selected_item = self.report["policies"][0]
        approve = self._main_query_one("#approve", Button)
        approve.disabled = (
            selected_item is None
            or not bool(selected_item.get("approval_eligible"))
        )
        if select_first and self.report["policies"]:
            self.selected_tool = str(self.report["policies"][0]["tool"])
            policy_list.index = 0
            self.call_after_refresh(self._render_selected_policy)
        elif self.selected_tool is not None:
            self.call_after_refresh(self._render_selected_policy)

    def _selected_report(self) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self.report["policies"]
                if item["tool"] == self.selected_tool
            ),
            None,
        )

    def _render_selected_policy(self) -> None:
        if self.selected_tool is None:
            return
        item = self._selected_report()
        if item is None:
            return
        approve = self._main_query_one("#approve", Button)
        approve.disabled = not bool(item.get("approval_eligible"))
        policy_path = self.workspace / "policies" / f"{self.selected_tool}.yaml"
        test_path = self.workspace / "tests" / f"{self.selected_tool}.yaml"
        try:
            policy = load_policy(policy_path)
            raw_policy = policy_path.read_text(encoding="utf-8")
            raw_tests = test_path.read_text(encoding="utf-8")
            project_document = yaml.safe_load(
                (self.workspace / "project.yaml").read_text(encoding="utf-8")
            )
            context_document = yaml.safe_load(
                (self.workspace / "context.yaml").read_text(encoding="utf-8")
            )
            test_result_document = (
                json.loads(
                    (self.workspace / "test-results.json").read_text(
                        encoding="utf-8"
                    )
                )
                if (self.workspace / "test-results.json").is_file()
                else {}
            )
        except (OSError, ValueError) as exc:
            self.push_screen(
                MessageScreen("Could not read policy", str(exc), error=True)
            )
            return
        self._main_query_one("#empty-detail", Static).display = False
        self._main_query_one("#policy-heading", Static).update(self.selected_tool)
        self._main_query_one("#policy-subheading", Static).update(
            f"{item['risk']} risk  |  "
            f"{item['status'].replace('_', ' ')}  |  "
            f"tests {item['tests']['passed']}/{item['tests']['total']}"
        )
        self._main_query_one("#property-content", Static).update(
            _property_table(policy)
        )
        self._main_query_one("#rules-content", Static).update(_rule_table(policy))
        self._main_query_one("#authoring-content", Static).update(
            _authoring_help(policy, project_document, context_document)
        )
        self._main_query_one(
            "#authoring-section",
            Collapsible,
        ).collapsed = bool(policy.rules)
        findings = item.get("unresolved_findings", item["blocking_findings"])
        warnings = self.report.get("warnings", [])
        self._main_query_one("#findings-content", Static).update(
            _findings_review(warnings, findings, item["questions"])
        )
        self._main_query_one(
            "#findings-section",
            Collapsible,
        ).collapsed = not bool(findings or warnings)
        selected_test_result = next(
            (
                result
                for result in test_result_document.get("results", [])
                if result.get("tool") == self.selected_tool
            ),
            None,
        )
        self._main_query_one("#tests-content", Static).update(
            _test_review(raw_tests, selected_test_result)
        )
        self._main_query_one("#raw-policy-content", Static).update(
            Markdown(f"```yaml\n{raw_policy}\n```")
        )
        self.call_after_refresh(self._scroll_detail_home)

    def _scroll_detail_home(self) -> None:
        self._main_query_one("#detail-scroll", VerticalScroll).scroll_home(
            animate=False
        )

    @on(ListView.Selected, "#policy-list")
    def select_policy(self, event: ListView.Selected) -> None:
        if event.item is None or event.item.name is None:
            return
        self.selected_tool = event.item.name
        self._render_selected_policy()

    @on(Button.Pressed, "#reload")
    def reload_button(self) -> None:
        self.action_reload()

    def action_reload(self) -> None:
        self._reload_report(run_tests=self.run_tests_on_reload)

    @on(Button.Pressed, "#run-tests")
    def tests_button(self) -> None:
        self.action_run_tests()

    def action_run_tests(self) -> None:
        self._reload_report(run_tests=True, success_message="Policy tests completed.")

    def _reload_report(
        self,
        *,
        run_tests: bool,
        success_message: str | None = None,
    ) -> None:
        try:
            self.report = build_workbench_report(
                self.workspace,
                run_tests=run_tests,
            )
        except (ValueError, RuntimeError) as exc:
            self.push_screen(MessageScreen("Workbench error", str(exc), error=True))
            return
        self._render_report()
        if success_message:
            self.notify(success_message)

    def _edit_path(self, path: Path, title: str, *, rerun_tests: bool) -> None:
        def completed(saved: bool | None) -> None:
            if not saved:
                return

            def finish_edit() -> None:
                self._reload_report(run_tests=rerun_tests)
                self.notify(f"Saved and validated {path.name}.")

            self.call_next(finish_edit)

        self.push_screen(EditorScreen(path, title, completed))

    @on(Button.Pressed, "#edit-policy")
    def edit_policy_button(self) -> None:
        self.action_edit_policy()

    def action_edit_policy(self) -> None:
        if self.selected_tool is None:
            return
        policy_path = (
            self.workspace / "policies" / f"{self.selected_tool}.yaml"
        )
        project_document = yaml.safe_load(
            (self.workspace / "project.yaml").read_text(encoding="utf-8")
        )
        context_document = yaml.safe_load(
            (self.workspace / "context.yaml").read_text(encoding="utf-8")
        )
        tool: dict[str, Any] = next(
            (
                item
                for item in project_document.get("tools", [])
                if item.get("name") == self.selected_tool
            ),
            {},
        )
        schema = tool.get("input_schema", {})
        properties = schema.get("properties", {})
        action_paths = [
            f"action.arguments.{name}"
            for name in sorted(properties)
        ]
        trusted_paths = [
            str(item["path"])
            for item in context_document.get("attributes", [])
            if item.get("path")
            and item.get("trust") not in {"model_provided", "untrusted"}
        ]
        operand_paths = [*action_paths, *trusted_paths]
        operand_types = {
            f"action.arguments.{name}": str(definition["type"])
            for name, definition in properties.items()
            if isinstance(definition, dict)
            and isinstance(definition.get("type"), str)
        }
        operand_types.update(
            {
                str(item["path"]): str(item["type"])
                for item in context_document.get("attributes", [])
                if item.get("path")
                and isinstance(item.get("type"), str)
            }
        )

        def completed(result: str | None) -> None:
            if result == "advanced":
                self.call_next(
                    lambda: self._edit_path(
                        policy_path,
                        f"Advanced policy YAML: {self.selected_tool}",
                        rerun_tests=True,
                    )
                )
                return
            if result != "saved":
                return
            self.call_next(
                lambda: self._reload_report(
                    run_tests=True,
                    success_message="Rule saved and policy tests rerun.",
                )
            )

        self.push_screen(
            RuleManagerScreen(
                policy_path,
                operand_paths,
                trusted_paths,
                operand_types,
                completed,
            )
        )

    @on(Button.Pressed, "#edit-tests")
    def edit_tests(self) -> None:
        if self.selected_tool is None:
            return
        self._edit_path(
            self.workspace / "tests" / f"{self.selected_tool}.yaml",
            f"Edit tests: {self.selected_tool}",
            rerun_tests=True,
        )

    @on(Button.Pressed, "#edit-context")
    def edit_context(self) -> None:
        self._edit_path(
            self.workspace / "context.yaml",
            "Advanced context contract",
            rerun_tests=True,
        )

    @on(Button.Pressed, "#approve")
    def approve_button(self) -> None:
        self.action_approve_policy()

    def action_approve_policy(self) -> None:
        if self.selected_tool is None:
            return
        item = self._selected_report()
        if item is None or not bool(item.get("approval_eligible")):
            return
        self._start_approval(self.selected_tool)

    @on(Button.Pressed, "#approve-all")
    def approve_all_button(self) -> None:
        self.action_approve_all_policies()

    def action_approve_all_policies(self) -> None:
        if not self.report["policies"] or any(
            not bool(item.get("approval_eligible"))
            for item in self.report["policies"]
        ):
            return
        self._start_approval(None)

    def _start_approval(self, tool_name: str | None) -> None:
        try:
            packet = build_approval_packet(
                self.workspace,
                tool_name=tool_name,
            )
        except ValueError as exc:
            self.push_screen(MessageScreen("Approval blocked", str(exc), error=True))
            return

        def completed(values: dict[str, Any] | None) -> None:
            if values is None:
                return

            def finish_approval() -> None:
                try:
                    count = approve_workspace(
                        self.workspace,
                        tool_name=tool_name,
                        **values,
                    )
                except (ValueError, RuntimeError) as exc:
                    self.push_screen(
                        MessageScreen("Approval failed", str(exc), error=True)
                    )
                    return
                self._reload_report(run_tests=self.run_tests_on_reload)
                label = "policy" if count == 1 else "policies"
                self.notify(f"Approved {count} {label}.")

            self.call_next(finish_approval)

        self.push_screen(
            ApprovalScreen(
                self.workspace,
                packet,
                tool_name,
                completed,
            )
        )

    @on(Button.Pressed, "#sync")
    def sync_source(self) -> None:
        def completed(confirmed: bool | None) -> None:
            if not confirmed:
                return

            def finish_sync() -> None:
                try:
                    result = refresh_workspace(self.workspace)
                except (ValueError, RuntimeError) as exc:
                    self.push_screen(
                        MessageScreen("Source sync failed", str(exc), error=True)
                    )
                    return
                self._reload_report(run_tests=self.run_tests_on_reload)
                message = (
                    "Source inventory synchronized. Approvals were invalidated "
                    "for deliberate rereview."
                    if result["applied"]
                    else "Source inventory is already current."
                )
                self.push_screen(MessageScreen("Source synchronization", message))

            self.call_next(finish_sync)

        self.push_screen(
            ReconciliationScreen(
                self.report["reconciliation"],
                completed,
            )
        )

    def action_sync_source(self) -> None:
        if self._main_query_one("#sync", Button).disabled:
            self.notify("Source synchronization is available only when changes exist.")
            return
        self.sync_source()

    @on(Button.Pressed, "#compile")
    def compile_button(self) -> None:
        self.action_compile_bundle()

    def action_compile_bundle(self) -> None:
        if self._main_query_one("#compile", Button).disabled:
            self.notify(
                "Compilation is available only after every policy is current, "
                "passing, and approved."
            )
            return

        def completed(options: dict[str, bool] | None) -> None:
            if options is None:
                return

            def finish_compile() -> None:
                try:
                    result = compile_workspace(
                        self.workspace,
                        require_validated=options["require_validated"],
                        require_exact_semantics=options[
                            "require_exact_semantics"
                        ],
                        allow_dirty_product=options["allow_dirty_product"],
                    )
                except (ValueError, RuntimeError) as exc:
                    self.push_screen(
                        MessageScreen("Compilation failed", str(exc), error=True)
                    )
                    return
                if not result.get("promoted"):
                    self.push_screen(
                        MessageScreen(
                            "Publication not promoted",
                            str(
                                result.get(
                                    "failure_report",
                                    "Compilation failed.",
                                )
                            ),
                            error=True,
                        )
                    )
                    return
                self._reload_report(run_tests=self.run_tests_on_reload)
                self.push_screen(
                    MessageScreen(
                        "Local bundle promoted",
                        f"Bundle: {result['bundle']}\n"
                        f"Digest: {result['bundle_digest']}",
                    )
                )

            self.call_next(finish_compile)

        self.push_screen(CompileScreen(completed))

    @on(Button.Pressed, "#export")
    def export_button(self) -> None:
        self.action_export_policy()

    def action_export_policy(self) -> None:
        if self.selected_tool is None:
            self.notify("Select a policy to export.")
            return
        if self._main_query_one("#export", Button).disabled:
            self.notify(
                "Export is available after the current approved workspace "
                "has been compiled."
            )
            return
        current_path = self.workspace / "generated" / "current.json"
        try:
            current = json.loads(current_path.read_text(encoding="utf-8"))
            bundle = (
                self.workspace / "generated" / str(current["bundle"])
            ).resolve(strict=True)
            verify_publication_bundle(bundle)
            package_root = bundle / self.selected_tool
            targets = sorted(
                (
                    item.name
                    for item in package_root.iterdir()
                    if item.is_dir() and item.name in TARGET_LABELS
                ),
                key=lambda target: list(TARGET_LABELS).index(target),
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self.push_screen(
                MessageScreen("Export unavailable", str(exc), error=True)
            )
            return
        if not targets:
            self.push_screen(
                MessageScreen(
                    "Export unavailable",
                    "The authoritative bundle has no exportable target package "
                    f"for {self.selected_tool}.",
                    error=True,
                )
            )
            return

        def completed(values: dict[str, Any] | None) -> None:
            if values is None:
                return

            def finish_export() -> None:
                try:
                    result = export_policy_package(
                        self.workspace,
                        tool_name=self.selected_tool or "",
                        **values,
                    )
                except (OSError, ValueError) as exc:
                    self.push_screen(
                        MessageScreen("Export failed", str(exc), error=True)
                    )
                    return
                label = TARGET_LABELS.get(
                    str(result["target"]),
                    str(result["target"]),
                )
                self.push_screen(
                    MessageScreen(
                        "Policy package exported",
                        f"Target: {label}\n"
                        f"ZIP: {result['archive']}\n"
                        f"Bundle: {result['bundle_digest']}",
                    )
                )

            self.call_next(finish_export)

        self.push_screen(
            ExportScreen(
                self.workspace,
                self.selected_tool,
                targets,
                completed,
            )
        )

    @on(Button.Pressed, "#verify")
    def verify_bundle(self) -> None:
        current_path = self.workspace / "generated" / "current.json"
        if not current_path.is_file():
            self.push_screen(
                MessageScreen(
                    "No promoted bundle",
                    "Compile the fully reviewed workspace before verification.",
                    error=True,
                )
            )
            return
        try:
            current = json.loads(current_path.read_text(encoding="utf-8"))
            bundle = self.workspace / "generated" / str(current["bundle"])
            result = verify_publication_bundle(bundle)
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            self.push_screen(
                MessageScreen("Bundle verification failed", str(exc), error=True)
            )
            return
        self.push_screen(
            MessageScreen(
                "Bundle integrity verified",
                f"Bundle: {bundle}\nArtifacts checked: {result['artifacts']}",
            )
        )

    def action_verify_bundle(self) -> None:
        self.verify_bundle()


def run_workbench_tui(
    workspace: Path,
    report: dict[str, Any],
    *,
    run_tests: bool,
) -> None:
    PolicyWorkbenchApp(workspace, report, run_tests=run_tests).run()
