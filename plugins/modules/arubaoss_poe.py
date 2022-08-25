#!/usr/bin/python
#
# Copyright (c) 2019 Hewlett Packard Enterprise Development LP
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
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: arubaoss_poe

short_description: implements rest api for PoE configuration

version_added: "2.4"

description:
    - "This implements rest apis which can be used to configure PoE"

options:
    command:
        description: The module to be called.
        choices: [ reset_poe_port, config_poe_port, config_poe_slot ]
        required: False
        default: config_poe_port
    port_id:
        description: The Port id
        required: False
    is_poe_enabled:
        description: The port PoE status
        required: False
    poe_priority:
        description: The port PoE priority
        choices: [ PPP_CRITICAL, PPP_HIGH, PPP_LOW ]
        required: False
        default: PPP_LOW
    poe_allocation_method:
        description: The PoE allocation method
        choices: [ PPAM_USAGE, PPAM_CLASS, PPAM_VALUE ]
        required: False
        default: PPAM_USAGE
    allocated_power_in_watts:
        description: Allocated power value. Default value for this is
                     platform dependent
        required: False
        default: 1
    port_configured_type:
        description:  Port configured type
        required: False
    pre_standard_detect_enabled:
        description: pre_std_detect enable or disable
        required: False
        default: False
    slot_name:
        description: The slot name
        required: False
    power_threshold_percentage:
        description: The power threshold percentage
        required: False

    host:
        description: >
            Specifies the DNS host name or address for connecting to the remote
            device over the specified transport. The value of host is used as the
            destination address for the transport.
        type: str
    password:
        description: >
            Specifies the password to use to authenticate the connection to the
            remote device. This value is used to authenticate the SSH session.
            If the value is not specified in the task, the value of environment
            variable ANSIBLE_NET_PASSWORD will be used instead.
        type: str
    port:
        description: >
            Specifies the port to use when building the connection to the remote
            device.
        type: int
    ssh_keyfile:
        description: >
            Specifies the SSH key to use to authenticate the connection to the
            remote device. This value is the path to the key used to
            authenticate the SSH session. If the value is not specified in the
            task, the value of environment variable ANSIBLE_NET_SSH_KEYFILE will
            be used instead.
        type: path
    timeout:
        description: >
            Specifies the timeout in seconds for communicating with the network
            device for either connecting or sending commands. If the timeout is
            exceeded before the operation is completed, the module will error.
        type: int
    username:
        description: >
            Configures the username to use to authenticate the connection to the
            remote device. This value is used to authenticate the SSH session.
            If the value is not specified in the task, the value of environment
            variable ANSIBLE_NET_USERNAME will be used instead.
        type: str
    use_ssl:
        description: >
            Configures use SSL (HTTPS) for access to the remote device.
        type: bool
    validate_certs:
        description: >
            Configures validation of certification for access to the remote device.
        type: bool
        default: False
    api_version:
        description: >
            Configures (force) API version (vX.Y) for acces to the remote device.
        type: str
        default: 'None'

    provider:
        description: A dict object containing connection details.
        type: dict
        suboptions:
            host:
                description: >
                    Specifies the DNS host name or address for connecting to the remote
                    device over the specified transport. The value of host is used as the
                    destination address for the transport.
                type: str
            password:
                description: >
                    Specifies the password to use to authenticate the connection to the
                    remote device. This value is used to authenticate the SSH session.
                    If the value is not specified in the task, the value of environment
                    variable ANSIBLE_NET_PASSWORD will be used instead.
                type: str
            port:
                description: >
                    Specifies the port to use when building the connection to the remote
                    device.
                type: int
            ssh_keyfile:
                description: >
                    Specifies the SSH key to use to authenticate the connection to the
                    remote device. This value is the path to the key used to
                    authenticate the SSH session. If the value is not specified in the
                    task, the value of environment variable ANSIBLE_NET_SSH_KEYFILE will
                    be used instead.
                type: path
            timeout:
                description: >
                    Specifies the timeout in seconds for communicating with the network
                    device for either connecting or sending commands. If the timeout is
                    exceeded before the operation is completed, the module will error.
                type: int
            username:
                description: >
                    Configures the username to use to authenticate the connection to the
                    remote device. This value is used to authenticate the SSH session.
                    If the value is not specified in the task, the value of environment
                    variable ANSIBLE_NET_USERNAME will be used instead.
                type: str
            use_ssl:
                description: >
                    Configures use SSL (HTTPS) for access to the remote device.
                type: bool
            validate_certs:
                description: >
                    Configures validation of certification for access to the remote device.
                type: bool
                default: False
            transport:
                description: >
                    Configures the transport (aossapi or network_cli) mode.
                type: str
                default: 'aossapi'
            use_proxy:
                description: >
                    Configures use (Local) Proxy for access to the remote device.
                type: bool
                default: False
            api_version:
                description: >
                    Configures (force) API version (vX.Y) for acces to the remote device.
                type: str
                default: 'None'
author:
    - Sanju Sadanandan (@hpe)
'''

EXAMPLES = '''
     - name: Updates poe port
       arubaoss_poe:
         command: config_poe_port
         port_id: 2
         is_poe_enabled: True
         poe_priority: "PPP_HIGH"
         poe_allocation_method: "PPAM_VALUE"
         allocated_power_in_watts: 15
         port_configured_type: ""
         pre_standard_detect_enabled: False

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA
import json  # NOQA


"""
-------
Name: config

Resets the PoE controller to which the port belongs

param request: module

Returns
 Configure the switch with params sent
-------
"""


def reset_poe_port(module):

    params = module.params
    data = {}

    # Check if port_id is null
    if params['port_id'] == "":
        return {'msg': 'port_id cannot be null',
                'changed': False, 'failed': False}

    url = '/poe/ports/' + str(params['port_id']) + '/reset'
    method = 'POST'

    result = run_commands(module, url, data, method, check=url)

    return result


"""
-------
Name: config

Resets the PoE controller to which the port belongs

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config_poe_port(module):

    params = module.params
    data = {}

    data['port_id'] = params['port_id']
    data['is_poe_enabled'] = params['is_poe_enabled']
    data['poe_priority'] = params['poe_priority']
    data['poe_allocation_method'] = params['poe_allocation_method']
    data['port_configured_type'] = params['port_configured_type']
    data['pre_standard_detect_enabled'] = params['pre_standard_detect_enabled']

    # allocated_power_in_watts can be set only when
    # poe_allocation_method is PPAM_VALUE
    if params['poe_allocation_method'] == "PPAM_VALUE":
        data['allocated_power_in_watts'] = params['allocated_power_in_watts']

    # Check if port_id is null
    if params['port_id'] == "":
        return {'msg': 'port_id cannot be null',
                'changed': False, 'failed': False}

    url = '/ports/' + str(params['port_id']) + '/poe'
    method = 'PUT'

    diffSeen = False
    check_presence = get_config(module, url)
    newdata = json.loads(check_presence)
    for key in data:
        if not newdata[key] == data[key]:
            diffSeen = True
            break

    if diffSeen:
        result = run_commands(module, url, data, method, check=url)
        return result
    else:
        return {'msg': 'Already Configured',
                'changed': False, 'failed': False}


"""
-------
Name: config

Resets the PoE controller to which the port belongs

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config_poe_slot(module):

    params = module.params
    data = {}

    data['slot_name'] = params['slot_name']
    data['power_threshold_percentage'] = params['power_threshold_percentage']

    # Check if slot_name is null
    if params['slot_name'] == "":
        return {'msg': 'slot_name cannot be null',
                'changed': False, 'failed': False}

    url = '/slots/' + str(params['slot_name']) + '/poe'
    method = 'PUT'

    diffSeen = False
    check_presence = get_config(module, url)
    newdata = json.loads(check_presence)
    for key in data:
        if not newdata[key] == data[key]:
            diffSeen = True
            break

    if diffSeen:
        result = run_commands(module, url, data, method, check=url)
        return result
    else:
        return {'msg': 'Already Configured',
                'changed': False, 'failed': False}


"""
-------
Name: run_module()

The main module invoked

Returns
 Configure the switch with params sent
-------
"""


def run_module():
    module_args = dict(
        command=dict(type='str', required=False, default="config_poe_port",
                     choices=["reset_poe_port",
                              "config_poe_port",
                              "config_poe_slot"]),
        port_id=dict(type='str', required=False, default=""),
        is_poe_enabled=dict(type='bool', required=False, default=True),
        poe_priority=dict(type='str', required=False, default="PPP_LOW",
                          choices=["PPP_CRITICAL",
                                   "PPP_HIGH",
                                   "PPP_LOW"]),
        poe_allocation_method=dict(type='str', required=False,
                                   default="PPAM_USAGE",
                                   choices=["PPAM_USAGE",
                                            "PPAM_CLASS",
                                            "PPAM_VALUE"]),
        allocated_power_in_watts=dict(type='int', required=False, default=1),
        port_configured_type=dict(type='str', required=False, default=""),
        pre_standard_detect_enabled=dict(type='bool', required=False,
                                         default=False),
        slot_name=dict(type='str', required=False, default=""),
        power_threshold_percentage=dict(type='int', required=False, default=1),
    )

    module_args.update(arubaoss_argument_spec)

    result = dict(changed=False, warnings='Not Supported')

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    try:
        if module.params['command'] == "reset_poe_port":
            result = reset_poe_port(module)
        if module.params['command'] == "config_poe_slot":
            result = config_poe_slot(module)
        else:
            result = config_poe_port(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
