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
module: arubaoss_mac_authentication

short_description: implements rest api for Mac Authentication

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure
       Mac Authentication"

options:
    command:
        description: The command to be configured
        required: False
        choices: [ configMacAuth, configMacAuthOnPort ]
        default: configMacAuth
        type: str
    port_id:
        description: The port id to be configured on the switch
        required: False
        default: ''
        type: str
    unauthorized_vlan_id:
        description: Unauthorized VLAN ID. If we are giving
                     unauthorized_vlan_id as 0,
                     it will remove the unauthorized_vlan_id configured
        required: False
        default: 0
        type: int
    is_mac_authentication_enabled:
        description: Enables/disables MAC authentication on the Port
        required: False
        default: True
        type: bool
    reauthenticate:
        description: Provides option on whether to reauthenticate
        required: False
        default: False
        type: bool
    mac_address_limit:
        description: The MAC Authentication address limit to be configured
        required: False
        default: 1
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
    - name: Updates Mac Authentication globally
      arubaoss_mac_authentication:
        command: "configMacAuth"
        unauthorized_vlan_id: 10

'''


from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA


"""
-------
Name: config

Configures mac authentication globally on the switch

param request: module

Returns
 Configure the switch with params sent
-------
"""


def configMacAuthOnPort(module):

    params = module.params
    data = {}

    if params['port_id'] == "":
        return {'msg': "Port Id cannot be null",
                'changed': False, 'failed': False}
    else:
        data['port_id'] = params['port_id']

    data['reauthenticate'] = params['reauthenticate']
    data['mac_address_limit'] = params['mac_address_limit']
    data['is_mac_authentication_enabled'] = \
        params['is_mac_authentication_enabled']

    # Verify if the vlans are already present
    if params['unauthorized_vlan_id']:
        check_presence = get_config(module, "/vlans/" +
                                    str(params['unauthorized_vlan_id']))
        if not check_presence:
            return {'msg': 'Cannot unauthorize the vlan without '
                    'Vlan configured', 'changed': False, 'failed': False}
        else:
            data['unauthorized_vlan_id'] = params['unauthorized_vlan_id']

    url = '/mac-authentication/port/' + str(params['port_id'])

    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: config

Configures mac authentication globally on the switch

param request: module

Returns
 Configure the switch with params sent
-------
"""


def configMacAuth(module):

    params = module.params
    data = {}

    # Verify if the vlans are already present
    if params['unauthorized_vlan_id']:
        check_presence = get_config(module, "/vlans/" +
                                    str(params['unauthorized_vlan_id']))
        if not check_presence:
            return {'msg': 'Cannot unauthorize the vlan without '
                    'Vlan configured', 'changed': False, 'failed': False}
        else:
            data['unauthorized_vlan_id'] = params['unauthorized_vlan_id']
    data['is_mac_authentication_enabled'] = \
        params['is_mac_authentication_enabled']

    url = '/mac-authentication'
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
        command=dict(type='str', required=False, default="configMacAuth",
                     choices=["configMacAuth", "configMacAuthOnPort"]),
        unauthorized_vlan_id=dict(type='int', required=False, default=0),
        port_id=dict(type='str', required=False, default=""),
        is_mac_authentication_enabled=dict(type='bool',
                                           required=False, default=True),
        mac_address_limit=dict(type='int', required=False, default=1),
        reauthenticate=dict(type='bool', required=False, default=False),
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
        if module.params['command'] == "configMacAuth":
            result = configMacAuth(module)
        else:
            result = configMacAuthOnPort(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
