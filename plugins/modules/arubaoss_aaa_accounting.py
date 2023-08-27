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
module: arubaoss_aaa_accounting

short_description: implements rest api for AAA Accounting configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure AAA Accounting"

options:
    cmd_accounting_method:
        description: Method for commands Accounting Configuration
        choices: [ AME_NONE, AME_TACACS, AME_RADIUS ]
        default: AME_NONE
        required: False
        type: str
    cmd_accounting_mode:
        description: Mode for commands Accounting Configuration
        choices: [ AMO_NONE, AMO_STOP_ONLY ]
        default: AMO_NONE
        required: False
        type: str
    cmd_server_group:
        description: Server Group for commands Accounting Configuration
        required: False
        default: ''
        type: str
    ntwk_accounting_method:
        description: Method for network Accounting Configuration
        choices: [ AME_NONE, AME_TACACS, AME_RADIUS ]
        default: AME_NONE
        required: False
        type: str
    ntwk_accounting_mode:
        description: Mode for network Accounting Configuration
        choices: [ AMO_NONE, AMO_STOP_ONLY, AMO_START_STOP ]
        default: AMO_NONE
        required: False
        type: str
    ntwk_server_group:
        description: Server Group for network Accounting Configuration
        required: False
        default: ''
        type: str
    update_interval:
        description: Update interval for accounting
        default: '0'
        required: False
        type: int

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
     - name: Updates the given accounting configuration to the system
       arubaoss_aaa_accounting:
         cmd_accounting_method: "AME_TACACS"
         cmd_accounting_mode: "AMO_STOP_ONLY"
         ntwk_accounting_method: "AME_NONE"
         ntwk_accounting_mode: "AMO_NONE"
         update_interval: 10
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA


"""
-------
Name: config_accounting

Configures port with mstp config

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config_accounting(module):

    params = module.params

    data = {}
    serverGrp = {}
    data['update_interval'] = params['update_interval']
    data['accounting_commands'] = {
        'accounting_method': params['cmd_accounting_method'],
        'accounting_mode': params['cmd_accounting_mode']
    }

    # Server Group name is not supported when accounting_method is AME_TACACS
    if not params['cmd_accounting_method'] == "AME_TACACS":
        serverGrp = {'server_group': params['cmd_server_group']}
    else:
        serverGrp = {'server_group': ""}

    data['accounting_commands'].update(serverGrp)

    data['accounting_network'] = {
        'accounting_method': params['ntwk_accounting_method'],
        'accounting_mode': params['ntwk_accounting_mode']
    }

    # Server Group name is not supported when accounting_method is AME_TACACS
    if not params['ntwk_accounting_method'] == "AME_TACACS":
        serverGrp = {'server_group': params['cmd_server_group']}
    else:
        serverGrp = {'server_group': ""}

    data['accounting_network'].update(serverGrp)

    url = '/accounting'
    method = 'PUT'

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
        cmd_accounting_method=dict(type='str', required=False,
                                   default='AME_NONE',
                                   choices=["AME_NONE",
                                            "AME_TACACS",
                                            "AME_RADIUS"]),
        cmd_accounting_mode=dict(type='str',
                                 required=False,
                                 default='AMO_NONE',
                                 choices=["AMO_NONE",
                                          "AMO_STOP_ONLY"]),
        ntwk_accounting_method=dict(type='str',
                                    required=False,
                                    default='AME_NONE',
                                    choices=["AME_NONE",
                                             "AME_TACACS",
                                             "AME_RADIUS"]),
        ntwk_accounting_mode=dict(type='str', required=False,
                                  default='AMO_NONE',
                                  choices=["AMO_NONE",
                                           "AMO_STOP_ONLY",
                                           "AMO_START_STOP"]),
        update_interval=dict(type='int', required=False, default='0'),
        cmd_server_group=dict(type='str', required=False, default=''),
        ntwk_server_group=dict(type='str', required=False, default=''),
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
        result = config_accounting(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
