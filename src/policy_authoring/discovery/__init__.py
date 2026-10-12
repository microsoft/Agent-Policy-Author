# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Bounded, adapter-based static discovery for agent projects."""

from policy_authoring.discovery.contracts import (
    BaseDiscoveryAdapter,
    DiscoveryAdapter,
    DiscoveryAdapterRegistry,
    DiscoveryContext,
    DiscoveryContribution,
    DiscoveryLimits,
)
from policy_authoring.discovery.registry import default_discovery_registry
from policy_authoring.discovery.scanner import (
    SUPPORTED_DISCOVERY_SUFFIXES,
    discover_project,
)

__all__ = [
    "BaseDiscoveryAdapter",
    "DiscoveryAdapter",
    "DiscoveryAdapterRegistry",
    "DiscoveryContext",
    "DiscoveryContribution",
    "SUPPORTED_DISCOVERY_SUFFIXES",
    "DiscoveryLimits",
    "default_discovery_registry",
    "discover_project",
]
