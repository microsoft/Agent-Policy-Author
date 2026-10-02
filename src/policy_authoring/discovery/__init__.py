# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Bounded static discovery for agent projects."""

from policy_authoring.discovery.scanner import (
    SUPPORTED_DISCOVERY_SUFFIXES,
    DiscoveryLimits,
    discover_project,
)

__all__ = [
    "SUPPORTED_DISCOVERY_SUFFIXES",
    "DiscoveryLimits",
    "discover_project",
]
