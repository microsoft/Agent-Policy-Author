# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import re

_READ_PREFIXES = ("get", "list", "read", "search", "find", "fetch", "inspect")
_WRITE_TOKENS = {
    "apply",
    "create",
    "delete",
    "deploy",
    "disable",
    "execute",
    "publish",
    "revoke",
    "remove",
    "send",
    "submit",
    "suspend",
    "terminate",
    "transfer",
    "update",
    "write",
}


def risk_for_tool(
    name: str,
    description: str,
    method: str | None = None,
) -> str:
    if method and method.lower() in {"get", "head", "options"}:
        return "read"
    lowered = re.sub(r"[^a-z0-9]+", " ", f"{name} {description}".lower())
    if name.lower().startswith(_READ_PREFIXES):
        return "read"
    if name.lower().startswith(("prepare", "confirm", "validate")):
        return "write"
    if any(token in lowered.split() for token in _WRITE_TOKENS):
        return "consequential-write"
    if method and method.lower() == "delete":
        return "consequential-write"
    if method and method.lower() in {"post", "put", "patch"}:
        return "write"
    return "unknown"
