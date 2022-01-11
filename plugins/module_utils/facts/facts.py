#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (C) Copyright 2021 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config, run_commands # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.interfaces import InterfacesFacts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.legacy import Default, HostSystemInfo, \
    SwitchSpecificSystemInfo, Modules, PowerSupplies
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.vlans import VlansFacts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.vlans_ports import VlansPortsFacts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.acls import AclsFacts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.lacp_interfaces import LacpInterfacesFacts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.lldp_neighbors import LldpNeighborsFacts
from ansible.module_utils.network.common.facts.facts import FactsBase
import json # NOQA


FACT_LEGACY_SUBSETS = dict(
    default=Default,
    host_system_info=HostSystemInfo,
    switch_specific_system_info=SwitchSpecificSystemInfo,
    module_info=Modules,
    system_power_supply=PowerSupplies,
)

FACT_RESOURCE_SUBSETS = dict(
    vlans=VlansFacts,
    vlans_ports=VlansPortsFacts,
    interfaces=InterfacesFacts,
    acls=AclsFacts,
    lldp_neighbors=LldpNeighborsFacts,
    lacp_interfaces=LacpInterfacesFacts
)


class Facts(FactsBase):
    '''
    Base class for  PVOS Facts
    '''
    VALID_LEGACY_GATHER_SUBSETS = frozenset(FACT_LEGACY_SUBSETS.keys())
    VALID_RESOURCE_SUBSETS = frozenset(FACT_RESOURCE_SUBSETS.keys())

    def get_facts(self, legacy_facts_type=None, resource_facts_type=None,
                  data=None):
        '''
        Returns the facts for PVOS
        '''
        if self.VALID_RESOURCE_SUBSETS:
            self.get_network_resources_facts(FACT_RESOURCE_SUBSETS,
                                             resource_facts_type, data)

        if self.VALID_LEGACY_GATHER_SUBSETS:
            self.get_network_legacy_facts(FACT_LEGACY_SUBSETS,
                                          legacy_facts_type)

        return self.ansible_facts, self._warnings
