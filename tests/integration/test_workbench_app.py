# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml
from rich.console import Console
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Input,
    Label,
    ListView,
    Select,
    Static,
    TextArea,
)

from policy_authoring.domain.models import Condition
from policy_authoring.ingestion.loader import load_policy
from policy_authoring.workbench_app import (
    PolicyWorkbenchApp,
    ReconciliationScreen,
    _findings_review,
    _generated_rule_id,
    _normalize_expiry,
    format_condition,
    policy_property_rows,
)
from policy_authoring.workspace import build_workbench_report, initialize_workspace


def _workspace(
    tmp_path: Path,
    *,
    targets: list[str] | None = None,
) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def update_record():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'update_record', 'Update record', 'records', True, False,\n"
        " update_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=targets or ["opa"])
    return workspace


def test_policy_review_format_explains_properties_and_mappings(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    policy = load_policy(workspace / "policies" / "update_record.yaml")

    rows = policy_property_rows(policy)
    row_by_name = {name: (value, guidance) for name, value, guidance in rows}

    assert row_by_name["Tool"][0] == "update_record"
    assert "action this policy governs" in row_by_name["Tool"][1]
    assert row_by_name["Default decision"][0] == "deny"
    assert "safe default" in row_by_name["Default decision"][1]
    assert "agent.py" in row_by_name["Source mapping"][0]
    condition = Condition.model_validate(
        {
            "operator": "equals",
            "left": {"path": "action.arguments.record_id"},
            "right": {"path": "resource.record_id"},
        }
    )
    assert format_condition(condition) == [
        "action.arguments.record_id EQUALS resource.record_id"
    ]


def test_workbench_renders_clickable_collapsible_policy_review(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            assert len(app.query(ListView)) == 1
            assert app.query_one("#property-section", Collapsible).collapsed is False
            assert app.query_one("#rules-section", Collapsible).collapsed is False
            raw = app.query_one("#raw-policy-section", Collapsible)
            assert raw.collapsed is True
            raw.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.click("#raw-policy-section CollapsibleTitle")
            await pilot.pause()
            assert raw.collapsed is False
            assert "READINESS" in str(
                app.query_one("#workspace-summary", Static).render()
            )
            assert "warnings 1" in str(
                app.query_one("#workspace-summary", Static).render()
            )
            assert not app.query_one("#run-tests", Button).disabled
            assert app.query_one("#compile", Button).disabled

    asyncio.run(exercise())


def test_findings_review_renders_styles_without_visible_markup() -> None:
    console = Console(record=True, width=100)
    console.print(
        _findings_review(
            ["Import runtime traces before relying on state binding."],
            ["incomplete_policy_synthesis"],
            ["Confirm the intended authorization behavior."],
        )
    )

    rendered = console.export_text()
    assert "[bold" not in rendered
    assert "Workspace warnings" in rendered
    assert "Unresolved findings" in rendered
    assert "Review questions" in rendered
    assert "• incomplete_policy_synthesis" in rendered


def test_generated_rule_ids_are_readable_and_unique() -> None:
    first = _generated_rule_id(
        "allow",
        "Allow updates only for the reviewed record.",
        set(),
    )
    second = _generated_rule_id(
        "allow",
        "Allow updates only for the reviewed record.",
        {first},
    )

    assert first == "allow-updates-only-for-the-reviewed-record"
    assert second == "allow-updates-only-for-the-reviewed-record-2"


def test_workbench_keeps_lifecycle_controls_visible_in_small_terminal(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            for button_id in (
                "#reload",
                "#edit-policy",
                "#edit-tests",
                "#edit-context",
                "#run-tests",
                "#approve",
                "#approve-all",
                "#sync",
                "#compile",
                "#verify",
            ):
                button = app.query_one(button_id, Button)
                assert button.region.height == 1
                assert button.region.y >= 0
                assert button.region.bottom <= app.size.height
                assert button.region.right <= app.size.width
            assert app.query_one("#detail-scroll").scroll_offset.y == 0
            detail = app.query_one("#detail-scroll")
            assert app.query_one("#property-content").region.y < detail.region.bottom
            await pilot.click("#approve")
            await pilot.pause()
            confirm = app.screen.query_one("#confirm-approval", Button)
            assert confirm.region.height == 1
            assert confirm.region.bottom <= app.size.height
            assert app.screen.query_one(
                "#approval-evidence",
                Collapsible,
            ).collapsed

    asyncio.run(exercise())


def test_workbench_keyboard_shortcuts_respect_disabled_lifecycle_actions(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.query_one("#sync", Button).disabled
            assert app.query_one("#compile", Button).disabled
            await pilot.press("s")
            await pilot.pause()
            assert len(app.screen_stack) == 1
            await pilot.press("c")
            await pilot.pause()
            assert len(app.screen_stack) == 1

    asyncio.run(exercise())


def test_workbench_policy_selection_updates_detail_panel(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def first_write(): pass\n"
        "def second_write(): pass\n"
        "SPECS = [\n"
        " ToolSpec('first_write', 'First', 'records', True, False,\n"
        "  first_write, schema(['record_id'], record_id='string')),\n"
        " ToolSpec('second_write', 'Second', 'records', True, False,\n"
        "  second_write, schema(['record_id'], record_id='string')),\n"
        "]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            policy_list = app.query_one("#policy-list", ListView)
            assert len(policy_list.children) == 2
            await pilot.click(policy_list.children[1])
            await pilot.pause()
            assert app.selected_tool == "second_write"
            assert "second_write" in str(
                app.query_one(".policy-heading", Static).render()
            )

    asyncio.run(exercise())


def test_workbench_offers_advanced_yaml_policy_editing(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            await pilot.click("#advanced-yaml")
            for _ in range(20):
                await pilot.pause(0.05)
                if app.screen.query("#yaml-editor"):
                    break
            editor = app.screen.query_one("#yaml-editor", TextArea)
            original = editor.text
            editor.load_text("rules: [\n")
            save_button = app.screen.query_one("#save", Button)
            save_button.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(save_button)
            await pilot.pause()
            assert "Not saved" in str(
                app.screen.query_one("#editor-error", Static).render()
            )
            assert (
                workspace / "policies" / "update_record.yaml"
            ).read_text(encoding="utf-8") == original
            document = yaml.safe_load(original)
            document["metadata"]["description"] = "Reviewed in the workbench"
            editor.load_text(yaml.safe_dump(document, sort_keys=False))
            await pilot.click(editor)
            save_button.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(save_button)
            for _ in range(40):
                await pilot.pause(0.05)
                if (
                    load_policy(
                        workspace / "policies" / "update_record.yaml"
                    ).metadata.description
                    == "Reviewed in the workbench"
                ):
                    break
            saved = load_policy(
                workspace / "policies" / "update_record.yaml"
            )
            assert saved.metadata.description == "Reviewed in the workbench"
            assert app.report["tests"]["status"] == "passed"

    asyncio.run(exercise())


def test_workbench_guides_rule_add_modify_and_delete(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    policy_path = workspace / "policies" / "update_record.yaml"
    document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    document["rules"] = []
    policy_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            async def wait_for_rule(rule_id: str, *, present: bool) -> None:
                for _ in range(40):
                    await pilot.pause(0.05)
                    ids = [rule.id for rule in load_policy(policy_path).rules]
                    if (rule_id in ids) is present:
                        return
                raise AssertionError(
                    f"rule {rule_id!r} presence did not become {present}"
                )

            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            app.screen.query_one("#rule-reason", Input).value = (
                "Allow updates only for the reviewed record."
            )
            app.screen.query_one("#condition-left-0", Select).value = (
                "action.arguments.record_id"
            )
            app.screen.query_one("#condition-right-kind-0", Select).value = (
                "literal"
            )
            app.screen.query_one("#condition-right-literal-0", Input).value = (
                "record-123"
            )
            save = app.screen.query_one("#save-rule", Button)
            save.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.click(save)
            generated_id = "allow-updates-only-for-the-reviewed-record"
            await wait_for_rule(generated_id, present=True)
            saved = load_policy(policy_path).rules[0]
            assert saved.id == generated_id
            assert saved.reason == "Allow updates only for the reviewed record."

            await pilot.click(app._main_query_one("#edit-policy", Button))
            await pilot.pause()
            app.screen.query_one("#rule-reason", Input).value = (
                "Allow the reviewed record update."
            )
            await pilot.click(app.screen.query_one("#save-rule", Button))
            for _ in range(40):
                await pilot.pause(0.05)
                if (
                    load_policy(policy_path).rules[0].reason
                    == "Allow the reviewed record update."
                ):
                    break
            assert (
                load_policy(policy_path).rules[0].reason
                == "Allow the reviewed record update."
            )

            await pilot.click(app._main_query_one("#edit-policy", Button))
            await pilot.pause()
            await pilot.click(app.screen.query_one("#delete-rule", Button))
            await pilot.pause()
            assert "Delete rule" in str(
                app.screen.query_one("#delete-confirmation", Static).render()
            )
            confirm_delete = app.screen.query_one("#confirm-delete", Button)
            confirm_delete.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(confirm_delete)
            await wait_for_rule(generated_id, present=False)

    asyncio.run(exercise())


def test_rule_manager_keeps_actions_reachable_in_small_terminal(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    policy_path = workspace / "policies" / "update_record.yaml"
    document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    document["rules"] = [
        {
            "id": "allow-reviewed-record",
            "decision": "allow",
            "reason": "Allow only the reviewed record.",
            "condition": {
                "operator": "equals",
                "left": {"path": "action.arguments.record_id"},
                "right": {"literal": "record-123"},
            },
        }
    ]
    policy_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            labels = "\n".join(
                str(label.render())
                for label in app.screen.query(Label)
                if label.display
            )
            for expected_label in {
                "Rule to edit",
                "Decision",
                "How multiple conditions combine",
                "Business justification",
                "Field to evaluate",
                "Operator",
                "Compare with",
                "Fixed comparison value",
            }:
                assert expected_label in labels
            assert "Rule ID" not in labels
            assert "generated automatically" in str(
                app.screen.query_one("#rule-id-help", Static).render()
            )
            assert (
                app.screen.query_one(
                    "#condition-left-0",
                    Select,
                ).region.width
                >= 40
            )
            app.screen.query_one("#rule-reason", Input).value = (
                "Allow only the reviewed record."
            )
            for selector in (
                "#add-condition",
                "#delete-rule",
                "#advanced-yaml",
                "#save-rule",
                "#cancel",
            ):
                button = app.screen.query_one(selector, Button)
                button.scroll_visible(animate=False, top=True)
                await pilot.pause()
                assert button.region.height == 1
                assert button.region.y >= 0
                assert button.region.bottom <= app.size.height
                assert button.region.right <= app.size.width
            save = app.screen.query_one("#save-rule", Button)
            save.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(save)
            for _ in range(20):
                await pilot.pause(0.05)
                if len(app.screen_stack) == 1:
                    break
            assert len(app.screen_stack) == 1

            await pilot.click(app._main_query_one("#edit-policy", Button))
            await pilot.pause()
            add_condition = app.screen.query_one("#add-condition", Button)
            add_condition.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(add_condition)
            assert app.screen.query_one("#condition-row-1").display
            delete = app.screen.query_one("#delete-rule", Button)
            delete.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(delete)
            cancel_delete = app.screen.query_one("#cancel-delete", Button)
            cancel_delete.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(cancel_delete)
            advanced = app.screen.query_one("#advanced-yaml", Button)
            advanced.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(advanced)
            for _ in range(20):
                await pilot.pause(0.05)
                if app.screen.query("#yaml-editor"):
                    break
            assert app.screen.query_one("#yaml-editor", TextArea)
            cancel_editor = app.screen.query_one("#cancel", Button)
            editor = app.screen.query_one("#yaml-editor", TextArea)
            assert cancel_editor.region.height == 1
            assert cancel_editor.region.bottom <= app.size.height
            assert editor.region.bottom <= cancel_editor.region.y
            assert await pilot.click(cancel_editor)
            for _ in range(20):
                await pilot.pause(0.05)
                if len(app.screen_stack) == 1:
                    break
            await pilot.click(app._main_query_one("#edit-policy", Button))
            await pilot.pause()
            cancel_manager = app.screen.query_one("#cancel", Button)
            cancel_manager.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(cancel_manager)

    asyncio.run(exercise())


def test_rule_manager_uses_friendly_required_field_errors(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            app.screen.query_one("#rule-choice", Select).value = "__new__"
            await pilot.pause()
            app.screen.query_one("#condition-left-0", Select).value = (
                "action.arguments.record_id"
            )
            app.screen.query_one("#condition-right-kind-0", Select).value = (
                "literal"
            )
            await pilot.pause()
            app.screen.query_one(
                "#condition-right-literal-0",
                Input,
            ).value = "record-123"
            save = app.screen.query_one("#save-rule", Button)
            save.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(save)
            error = str(app.screen.query_one("#rule-error", Static).render())
            assert "Enter a business justification" in error
            assert "errors.pydantic.dev" not in error
            assert "String should match pattern" not in error

    asyncio.run(exercise())


def test_rule_manager_rejects_literal_with_incompatible_field_type(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            app.screen.query_one("#rule-choice", Select).value = "__new__"
            await pilot.pause()
            app.screen.query_one("#rule-reason", Input).value = (
                "Allow records above the reviewed threshold."
            )
            app.screen.query_one("#condition-left-0", Select).value = (
                "action.arguments.record_id"
            )
            app.screen.query_one("#condition-operator-0", Select).value = (
                "greater_than_or_equal"
            )
            app.screen.query_one("#condition-right-kind-0", Select).value = (
                "literal"
            )
            await pilot.pause()
            app.screen.query_one(
                "#condition-right-literal-0",
                Input,
            ).value = "123"
            save = app.screen.query_one("#save-rule", Button)
            save.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(save)
            error = str(app.screen.query_one("#rule-error", Static).render())
            assert "action.arguments.record_id expects text" in error
            assert 'Quote numeric-looking text, for example "123"' in error
            assert len(app.screen_stack) == 2

    asyncio.run(exercise())


def test_rule_manager_shows_list_value_input_when_operator_changes(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            for _ in range(2):
                add = app.screen.query_one("#add-condition", Button)
                add.scroll_visible(animate=False)
                await pilot.pause()
                assert await pilot.click(add)
            operator = app.screen.query_one("#condition-operator-2", Select)
            operator.value = "in"
            await pilot.pause()
            value_input = app.screen.query_one(
                "#condition-right-literal-2",
                Input,
            )
            value_label = app.screen.query_one(
                "#condition-value-label-2",
                Label,
            )
            row = app.screen.query_one("#condition-row-2")
            assert value_input.display
            assert "Comparison values" in str(value_label.render())
            assert value_input.region.width >= 40
            assert value_input.region.height > 0
            assert value_input.region.bottom <= row.region.bottom
            assert value_input.region.y >= 0
            assert value_input.region.bottom <= app.size.height

    asyncio.run(exercise())


def test_rule_manager_never_truncates_oversized_existing_rule(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    policy_path = workspace / "policies" / "update_record.yaml"
    document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    document["rules"] = [
        {
            "id": "allow-reviewed-record",
            "decision": "allow",
            "reason": "Preserve every reviewed constraint.",
            "condition": {
                "operator": "all",
                "conditions": [
                    {
                        "operator": "equals",
                        "left": {"path": "action.arguments.record_id"},
                        "right": {"literal": f"record-{index}"},
                    }
                    for index in range(9)
                ],
            },
        }
    ]
    policy_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#edit-policy")
            await pilot.pause()
            assert app.screen.query_one("#save-rule", Button).disabled
            assert "without truncating" in str(
                app.screen.query_one("#rule-error", Static).render()
            )
            assert len(load_policy(policy_path).rules[0].condition.conditions) == 9
            advanced = app.screen.query_one("#advanced-yaml", Button)
            advanced.scroll_visible(animate=False, top=True)
            await pilot.pause()
            assert await pilot.click(advanced)
            for _ in range(20):
                await pilot.pause(0.05)
                if app.screen.query("#yaml-editor"):
                    break
            editor_document = yaml.safe_load(
                app.screen.query_one("#yaml-editor", TextArea).text
            )
            assert len(editor_document["rules"][0]["condition"]["conditions"]) == 9

    asyncio.run(exercise())


def test_approval_shows_accepted_risk_fields_and_friendly_date_error(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def create_order():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'create_order', 'Create order', 'procurement', True, True,\n"
        " create_order, schema(['vendor_id'], vendor_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#approve")
            await pilot.pause()
            risk_fields = app.screen.query_one("#accepted-risk-fields-0")
            assert not risk_fields.display
            app.screen.query_one("#disposition-0", Select).value = (
                "accepted_risk"
            )
            await pilot.pause()
            assert risk_fields.display
            visible_labels = "\n".join(
                str(label.render())
                for label in risk_fields.query(Label)
                if label.display
            )
            assert "Risk expiry date *" in visible_labels
            assert "Compensating controls *" in visible_labels

            app.screen.query_one("#reviewer", Input).value = (
                "reviewer@example.com"
            )
            app.screen.query_one("#reviewer-role", Input).value = (
                "service-owner"
            )
            app.screen.query_one("#rationale", Input).value = (
                "Reviewed host evidence and generated policy tests."
            )
            app.screen.query_one("#finding-rationale-0", Input).value = (
                "Temporary risk is bounded by reviewed safeguards."
            )
            app.screen.query_one("#finding-evidence-0", Input).value = (
                "ticket://risk-123"
            )
            app.screen.query_one("#finding-expiry-0", Input).value = (
                "October someday"
            )
            app.screen.query_one("#finding-controls-0", Input).value = (
                "daily audit review"
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            confirm = app.screen.query_one("#confirm-approval", Button)
            confirm.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(confirm)
            error = str(
                app.screen.query_one("#approval-error", Static).render()
            )
            assert "YYYY-MM-DD or MM/DD/YYYY" in error
            assert "errors.pydantic.dev" not in error
            app.screen.query_one("#finding-expiry-0", Input).value = (
                "2000-01-01"
            )
            await pilot.pause()
            confirm.press()
            await pilot.pause()
            error = str(
                app.screen.query_one("#approval-error", Static).render()
            )
            assert "risk expiry must be a future date" in error

    asyncio.run(exercise())


def test_normalize_expiry_accepts_friendly_date_formats() -> None:
    assert _normalize_expiry("2026-10-31") == (
        "2026-10-31T23:59:59+00:00"
    )
    assert _normalize_expiry("10/31/2026") == (
        "2026-10-31T23:59:59+00:00"
    )
    with pytest.raises(ValueError, match="YYYY-MM-DD or MM/DD/YYYY"):
        _normalize_expiry("October someday")


def test_workbench_approves_compiles_and_verifies_bundle(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, targets=["opa", "acs"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            await pilot.click("#approve")
            await pilot.pause()
            app.screen.query_one("#reviewer", Input).value = "reviewer@example.com"
            app.screen.query_one("#reviewer-role", Input).value = "service-owner"
            app.screen.query_one("#rationale", Input).value = (
                "Reviewed mappings, rules, evidence, and passing tests."
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            await pilot.click(
                app.screen.query_one("#confirm-approval", Button)
            )
            await pilot.pause(0.2)
            review = yaml.safe_load(
                (workspace / "review.yaml").read_text(encoding="utf-8")
            )
            assert review["actions"][0]["review_status"] == "approved"
            assert app.report["summary"]["approved"] == 1
            assert not app._main_query_one("#compile", Button).disabled
            await pilot.click(app._main_query_one("#compile", Button))
            await pilot.pause()
            app.screen.query_one("#require-validated", Checkbox).value = False
            await pilot.click(
                app.screen.query_one("#confirm-compile", Button)
            )
            await pilot.pause(0.5)
            assert (workspace / "generated" / "current.json").is_file()
            assert "Local bundle promoted" in str(
                app.screen.query_one(".dialog-title", Static).render()
            )
            await pilot.click(app.screen.query_one("#close", Button))
            await pilot.pause()
            await pilot.click(app._main_query_one("#verify", Button))
            await pilot.pause()
            assert "Bundle integrity verified" in str(
                app.screen.query_one(".dialog-title", Static).render()
            )
            await pilot.click(app.screen.query_one("#close", Button))
            await pilot.pause()
            assert not app._main_query_one("#export", Button).disabled
            await pilot.click(app._main_query_one("#export", Button))
            await pilot.pause()
            target = app.screen.query_one("#export-target", Select)
            assert target.value == "acs"
            assert "microsoft-agent-governance-toolkit-acs" in (
                app.screen.query_one("#export-destination", Input).value
            )
            destination = tmp_path / "exports" / "agt-policy.zip"
            app.screen.query_one("#export-destination", Input).value = str(
                destination
            )
            await pilot.click(
                app.screen.query_one("#confirm-export", Button)
            )
            await pilot.pause(0.3)
            assert destination.is_file()
            assert "Policy package exported" in str(
                app.screen.query_one(".dialog-title", Static).render()
            )

    asyncio.run(exercise())


def test_workbench_syncs_source_changes_after_confirmation(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    source_file = tmp_path / "source" / "agent.py"
    source_file.write_text(
        source_file.read_text(encoding="utf-8").replace(
            "schema(['record_id'], record_id='string')",
            "schema(['record_id', 'audit_reason'], "
            "record_id='string', audit_reason='string')",
        ),
        encoding="utf-8",
    )
    report = build_workbench_report(workspace, run_tests=False)
    assert report["readiness"] == "needs_reconciliation"
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            assert not app.query_one("#sync", Button).disabled
            await pilot.click("#sync")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, ReconciliationScreen)
            assert "audit_reason" in json.dumps(screen.reconciliation)
            screen.query_one(
                "#confirm-reconciliation",
                Checkbox,
            ).value = True
            await pilot.click(
                screen.query_one("#confirm-reconciliation-sync", Button)
            )
            await pilot.pause()
            project = yaml.safe_load(
                (workspace / "project.yaml").read_text(encoding="utf-8")
            )
            assert "audit_reason" in project["tools"][0]["input_schema"]["required"]
            assert app.report["readiness"] == "needs_review"

    asyncio.run(exercise())


def test_workbench_approval_remains_scoped_to_selected_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def first_write():\n"
        "    check_approval()\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "def second_write():\n"
        "    check_approval()\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [\n"
        " ToolSpec('first_write', 'First', 'records', True, True,\n"
        "  first_write, schema(['record_id'], record_id='string')),\n"
        " ToolSpec('second_write', 'Second', 'records', True, True,\n"
        "  second_write, schema(['record_id'], record_id='string')),\n"
        "]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            policy_list = app.query_one("#policy-list", ListView)
            await pilot.click(policy_list.children[1])
            await pilot.pause()
            await pilot.click("#approve")
            await pilot.pause()
            app.screen.query_one("#reviewer", Input).value = "reviewer@example.com"
            app.screen.query_one("#rationale", Input).value = (
                "Reviewed only the selected policy and its evidence."
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            await pilot.click(
                app.screen.query_one("#confirm-approval", Button)
            )
            await pilot.pause(0.2)
            review = yaml.safe_load(
                (workspace / "review.yaml").read_text(encoding="utf-8")
            )
            actions = {item["tool"]: item for item in review["actions"]}
            assert actions["first_write"]["review_status"] == "needs_review"
            assert actions["second_write"]["review_status"] == "approved"

    asyncio.run(exercise())


def test_workbench_approves_all_policies_with_one_evidence_packet(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def first_write():\n"
        "    check_approval()\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "def second_write():\n"
        "    check_approval()\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [\n"
        " ToolSpec('first_write', 'First', 'records', True, True,\n"
        "  first_write, schema(['record_id'], record_id='string')),\n"
        " ToolSpec('second_write', 'Second', 'records', True, True,\n"
        "  second_write, schema(['record_id'], record_id='string')),\n"
        "]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            await pilot.click("#approve-all")
            await pilot.pause()
            assert "Approve all 2 policies" in str(
                app.screen.query_one(".dialog-title", Label).render()
            )
            app.screen.query_one("#reviewer", Input).value = "reviewer@example.com"
            app.screen.query_one("#rationale", Input).value = (
                "Reviewed both policies, their mappings, evidence, and tests."
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            await pilot.click(
                app.screen.query_one("#confirm-approval", Button)
            )
            await pilot.pause(0.2)
            review = yaml.safe_load(
                (workspace / "review.yaml").read_text(encoding="utf-8")
            )
            assert {
                item["tool"]: item["review_status"]
                for item in review["actions"]
            } == {
                "first_write": "approved",
                "second_write": "approved",
            }
            assert app.report["summary"]["approved"] == 2

    asyncio.run(exercise())


def test_workbench_shows_disabled_approval_for_incomplete_policies(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "def first_action(): pass\n"
        "def second_action(): pass\n"
        "SPECS = [\n"
        " ToolSpec('first_action', 'First', 'records', False, False,\n"
        "  first_action, schema(['record_id'], record_id='string')),\n"
        " ToolSpec('second_action', 'Second', 'records', False, False,\n"
        "  second_action, schema(['record_id'], record_id='string')),\n"
        "]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    assert all(
        "incomplete_policy_synthesis" in item["unresolved_findings"]
        for item in report["policies"]
    )
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            approve = app.query_one("#approve", Button)
            approve_all = app.query_one("#approve-all", Button)
            assert approve.disabled
            assert approve.display
            assert approve_all.disabled
            assert approve_all.display
            await pilot.press("a")
            await pilot.pause()
            assert len(app.screen_stack) == 1

    asyncio.run(exercise())


def test_workbench_collects_finding_disposition_before_approval(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "    expected_version: int\n"
        "    idempotency_key: str\n"
        "def create_order():\n"
        "    check_version()\n"
        "    execute_idempotent()\n"
        "    record_mutation()\n"
        "SPECS = [ToolSpec(\n"
        " 'create_order', 'Create order', 'procurement', True, True,\n"
        " create_order, schema(['vendor_id'], vendor_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)) as pilot:
            await pilot.pause()
            await pilot.click("#approve")
            await pilot.pause()
            app.screen.query_one("#reviewer", Input).value = "reviewer@example.com"
            app.screen.query_one("#reviewer-role", Input).value = "service-owner"
            app.screen.query_one("#rationale", Input).value = (
                "Reviewed host evidence and the generated policy tests."
            )
            app.screen.query_one("#disposition-0", Select).value = "false_positive"
            app.screen.query_one("#finding-rationale-0", Input).value = (
                "The host enforces approval before invoking this tool."
            )
            app.screen.query_one("#finding-evidence-0", Input).value = (
                "src://host/approval.py:42"
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            confirm = app.screen.query_one("#confirm-approval", Button)
            confirm.scroll_visible(animate=False)
            await pilot.pause()
            assert await pilot.click(confirm)
            await pilot.pause()
            assert "changed the approval snapshot" in str(
                app.screen.query_one("#approval-error", Static).render()
            )
            app.screen.query_one("#confirm-snapshot", Checkbox).value = True
            await pilot.pause()
            confirm.press()
            for _ in range(40):
                await pilot.pause(0.05)
                review = yaml.safe_load(
                    (workspace / "review.yaml").read_text(encoding="utf-8")
                )
                if "approval" in review["actions"][0]:
                    break
            disposition = review["actions"][0]["approval"][
                "finding_dispositions"
            ][0]
            assert disposition["disposition"] == "false_positive"
            assert disposition["evidence"] == ["src://host/approval.py:42"]
            assert app.report["summary"]["blocking_findings"] == 0

    asyncio.run(exercise())


def test_workbench_expands_authoring_help_for_policy_without_allow_path(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_text(
        "class ToolContext:\n"
        "    operation_id: str\n"
        "def delete_record(): pass\n"
        "SPECS = [ToolSpec(\n"
        " 'delete_record', 'Delete record', 'records', True, False,\n"
        " delete_record, schema(['record_id'], record_id='string'))]\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    initialize_workspace(source, workspace, targets=["opa"])
    policy_path = workspace / "policies" / "delete_record.yaml"
    policy_document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy_document["rules"] = []
    policy_path.write_text(
        yaml.safe_dump(policy_document, sort_keys=False),
        encoding="utf-8",
    )
    report = build_workbench_report(workspace, run_tests=True)
    app = PolicyWorkbenchApp(workspace, report, run_tests=True)

    async def exercise() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            policy = load_policy(policy_path)
            assert not any(rule.decision == "allow" for rule in policy.rules)
            assert not app.query_one(
                "#authoring-section",
                Collapsible,
            ).collapsed

    asyncio.run(exercise())
