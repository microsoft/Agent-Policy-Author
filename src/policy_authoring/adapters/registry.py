# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from policy_authoring.adapters.acs import AcsAdapter
from policy_authoring.adapters.agent_hooks import AgentHooksAdapter
from policy_authoring.adapters.base import AdapterRegistry
from policy_authoring.adapters.cedar import CedarAdapter
from policy_authoring.adapters.cerbos import CerbosAdapter
from policy_authoring.adapters.opa import OpaAdapter


def default_registry() -> AdapterRegistry:
    return AdapterRegistry(
        [
            AgentHooksAdapter(),
            OpaAdapter(),
            CedarAdapter(),
            CerbosAdapter(),
            AcsAdapter(),
        ]
    )
