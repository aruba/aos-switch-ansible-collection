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
module: arubaoss_stp

short_description: implements rest api for stp configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure STP"

options:
    command:
        description: Function name calls according to configuration required
        choices: [ config_spanning_tree, config_spanning_tree_port ]
        required: False
        default: config_spanning_tree
        type: str
    config:
        description: To config or unconfig the required command
        choices: [ create, delete ]
        required: False
        default: create
        type: str
    mode:
        description: MSTP or RPVST
        choices: [ STM_MSTP, STM_RPVST ]
        required: False
        default: STM_MSTP
        type: str
    priority:
        description: STP priority
        required: False
        default: 8
        type: int
    port_id:
        description: ID of the port
        required: False
        type: str
    is_enable_admin_edge_port:
        description: Enable/Disable admin-edge-port
        required: False
        default: False
        type: bool
    is_enable_bpdu_protection:
        description: Enable/Disable bpdu-protection.
        required: False
        default: False
        type: bool
    is_enable_bpdu_filter:
        description: Enable/Disable bpdu-filter.
        required: False
        default: False
        type: bool
    is_enable_root_guard:
        description: Enable/Disable root-guard.
        required: False
        default: False
        type: bool

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
     - name: update spanning tree port
       arubaoss_stp:
         port_id: 2
         mode:  "STM_MSTP"
         priority: 2
         is_enable_bpdu_protection: True
         is_enable_bpdu_filter: True
         is_enable_root_guard: True
         command: config_spanning_tree_port
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA


"""
-------
Name: config_spanning_tree

Configures Spanning Tree on device

param request: module

Returns
 The switch with params configured
-------
"""


def config_spanning_tree(module):

    params = module.params
    url = "/stp"
    data = {}

    if params['config'] == "create":
        data = {'is_enabled': True}
    else:
        data = {'is_enabled': False}

    data['priority'] = params['priority']
    data['mode'] = params['mode']

    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: config_spanning_tree_port

Configures port with stp config

param request: module

Returns
 The switch with params configured
-------
"""


def config_spanning_tree_port(module):

    params = module.params
    data = {}

    if params['port_id'] == "":
        return {'msg': 'Port Id cannot be null',
                'changed': False, 'failed': False}
    else:
        data['port_id'] = params['port_id']

    data['priority'] = params['priority']
    data['is_enable_admin_edge_port'] = params['is_enable_admin_edge_port']
    data['is_enable_bpdu_protection'] = params['is_enable_bpdu_protection']
    data['is_enable_bpdu_filter'] = params['is_enable_bpdu_filter']
    data['is_enable_root_guard'] = params['is_enable_root_guard']

    url = "/stp/ports/" + str(params['port_id'])

    # Check if spanning tree is enabled
    check_presence = get_config(module, '/stp')
    if check_presence:
        method = 'PUT'
    else:
        return {'msg': 'Cannot configure MST on port without '
                'spanning tree enabled', 'changed': False, 'failed': False}

    result = run_commands(module, url, data, method, check=url)
    return result


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
        command=dict(type='str', required=False,
                     default='config_spanning_tree',
                     choices=['config_spanning_tree',
                              'config_spanning_tree_port']),
        config=dict(type='str', required=False, default="create",
                    choices=['create', 'delete']),
        port_id=dict(type='str', required=False, default=""),
        priority=dict(type='int', required=False, default=8),
        mode=dict(type='str', required=False, default="STM_MSTP",
                  choices=["STM_MSTP", "STM_RPVST"]),
        is_enable_admin_edge_port=dict(type='bool', required=False,
                                       default=False),
        is_enable_bpdu_protection=dict(type='bool', required=False,
                                       default=False),
        is_enable_bpdu_filter=dict(type='bool', required=False,
                                   default=False),
        is_enable_root_guard=dict(type='bool', required=False, default=False),
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
        if module.params['command'] == "config_spanning_tree":
            result = config_spanning_tree(module)
        else:
            result = config_spanning_tree_port(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
