# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Static discovery fixture. This file is inspected but never executed."""

from collections.abc import Callable
from typing import Any, Literal, TypeVar

ToolFunction = TypeVar("ToolFunction", bound=Callable[..., Any])


def tool(function: ToolFunction) -> ToolFunction:
    return function


@tool
def prepare_update(
    document_id: str,
    field: str,
    value: str,
) -> dict[str, object]:
    """Prepare an inert document update."""
    raise RuntimeError("Static discovery fixture only")


@tool
def confirm_update(operation_id: str, digest: str) -> dict[str, object]:
    """Confirm an inert document update."""
    raise RuntimeError("Static discovery fixture only")


@tool
def apply_update(
    operation_id: str,
    document_id: str,
    field: str,
    value: str,
    digest: str,
    route: Literal["primary", "shadow"],
) -> dict[str, object]:
    """Apply an inert document update."""
    raise RuntimeError("Static discovery fixture only")
