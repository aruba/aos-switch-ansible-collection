#!/usr/bin/python
#
# Copyright (c) 2021 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = '''
---
module: arubaoss_facts
version_added: "2.10"
short_description: Collects facts from remote PVOS device
description:
  - This module retrieves facts from Aruba devices running the PVOS operating system. 
    Facts will be printed out when the playbook execution is done with increased verbosity.
author: Stella Rajan
options:

  gather_subset: 
    description: 
      - Retrieve a subset of all device information. This can be a single
        category or it can be a list. As warning, leaving this field blank
        returns all facts, which may be an intensive process.
    choices: ['host_system_info', 'switch_specific_system_info',
            'module_info', 'system_power_supply']
    required: False
    default: ['host_system_info', 'switch_specific_system_info',
            'module_info', 'system_power_supply']
    type: list

  gather_network_resources: 
    description:
      - Retrieve vlan, interface, acl, lacp interfaces or lldp neighbors information.
        This can be a single category or it can be a list. Leaving this field blank
        returns all interfaces, vlans, vlan-port assignments, loop protect status/ports/vlans, acl, lacp interfaces and lldp neighbors.
    choices: ['interfaces', 'vlans', 'vlans_ports', 'loop_protect_status', 'loop_protect_ports', 'loop_protect_vlans', 'acls', 'lacp_interfaces', 'lldp_neighbors']
    required: False
    type: list

  provider:
    description: A dict object containing connection details.
    suboptions:
      host:
        description:
          - Specifies the DNS host name or address for connecting to the remote device over the
            specified transport. The value of host is used as the destination address for the transport.
        required: True
        type: str
      password:
        description:
          - Specifies the password to use to authenticate the connection to the remote device.
            This value is used to authenticate the SSH session. If the value is not specified
            in the task, the value of environment variable ANSIBLE_NET_PASSWORD will be used instead.
        type: str
      port:
        description:
          - Specifies the port to use when building the connection to the remote device.
        type: int
      username:
        description:
          - Configures the username to use to authenticate the connection to the remote device.
            This value is used to authenticate the SSH session. If the value is not specified in the task,
            the value of environment variable ANSIBLE_NET_USERNAME will be used instead.
        type: str
    type: dict

'''  # NOQA

EXAMPLES = '''
- name: Retrieve all information from the device and save into a variable "facts_output"
  arubaoss_facts:
  register: facts_output

- name: Retrieve power supply and modules info from the device
  arubaoss_facts:
    gather_subset: ['system_power_supply', 'module_info']

- name: Retrieve ACL info and host system info from the device and save into a variable
  arubaoss_facts:
    gather_subset: ['host_system_info']
    gather_network_resources: ['acls']
  register: facts_subset_output
'''  # NOQA

RETURN = r'''
ansible_net_gather_subset:
  description: The list of fact subsets collected from the device
  returned: always
  type: list
ansible_net_gather_network_resources:
  description: The list of fact for network resource subsets collected from the device
  returned: when the resource is configured
  type: list
# default
ansible_net_host_system_info:
  description: The host system info returned from the device
  returned: always
  type: dict
ansible_net_switch_specific_system_info:
  description: The switch specific system info returned from the device
  returned: always
  type: dict
ansible_net_module_info:
  description: The modules info returned from the device
  returned: always
  type: dict
# hardware
ansible_net_system_power_supply:
  description: All power supplies available on the device
  returned: always
  type: dict
# interfaces
ansible_net_interfaces:
  description: A dictionary of all interfaces running on the system
  returned: always
  type: dict
'''

from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.facts.facts import Facts
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec, get_connection
from ansible.module_utils.basic import AnsibleModule
import json # NOQA

def main():
    """
    Main entry point for module execution
    :returns: ansible_facts
    """
    argument_spec = {
        'gather_subset': dict(default=['host_system_info',
                                   'switch_specific_system_info',
                                   'module_info',
                                   'system_power_supply'],
                              type='list',
                              choices=['host_system_info',
                                       'switch_specific_system_info',
                                       'module_info',
                                       'system_power_supply']),
        'gather_network_resources': dict(type='list',
                                         choices=['interfaces', 'vlans', 'vlans_ports',
                                                  'loop_protect_status', 'loop_protect_ports', 'loop_protect_vlans',
                                                  'acls', 'lldp_neighbors',
                                                  'lacp_interfaces'])
    }

    argument_spec.update(arubaoss_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    module._connection = get_connection(module)  # noqa

    warnings = []

    result = Facts(module).get_facts()

    ansible_facts, additional_warnings = result
    warnings.extend(additional_warnings)

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)

if __name__ == '__main__':
    main()
