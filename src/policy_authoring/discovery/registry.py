# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from policy_authoring.discovery.adapters.formats import (
    OpenApiDiscoveryAdapter,
    ProjectDefinitionAdapter,
    ToolManifestDiscoveryAdapter,
)
from policy_authoring.discovery.adapters.python import PythonDiscoveryAdapter
from policy_authoring.discovery.adapters.traces import AgentHooksTraceAdapter
from policy_authoring.discovery.adapters.typescript import (
    TypeScriptDiscoveryAdapter,
)
from policy_authoring.discovery.contracts import DiscoveryAdapterRegistry


def default_discovery_registry() -> DiscoveryAdapterRegistry:
    return DiscoveryAdapterRegistry(
        [
            ProjectDefinitionAdapter(),
            PythonDiscoveryAdapter(),
            TypeScriptDiscoveryAdapter(),
            OpenApiDiscoveryAdapter(),
            ToolManifestDiscoveryAdapter(),
            AgentHooksTraceAdapter(),
        ]
    )
