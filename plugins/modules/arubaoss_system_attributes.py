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
module: arubaoss_system_attributes

short_description: implements rest api for system attributes

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure system attributes"

options:
    hostname:
        description: The system name
        required: False
        type: str
    location:
        description: Location where the system is installed
        required: False
        type: str
    contact:
        description: Contact information for the system.
        required: False
        type: str
    domain_name:
        description: Regulatory domain where the system is operating on
        required: False
        type: str
    version:
        description: Version of ip address
        required: False
        choices: [ IAV_IP_V4, IAV_IP_V6 ]
        default: IAV_IP_V4
        type: str
    device_operation_mode:
        description: Mode in which the device is operating on
        required: False
        choices: [ DOM_CLOUD, DOM_CLOUD_WITH_SUPPORT, DOM_AUTONOMOUS ]
        default: DOM_AUTONOMOUS
        type: str
    uplink_vlan_id:
        description: Vlan via which central is connected. This is applicable
                     only when device_operation_mode is DOM_CLOUD or
                     DOM_CLOUD_WITH_SUPPORT. This won't be available for
                     non Central uses case
        required: False
        type: str
    uplink_ip:
        description: Ip address of Vlan via which central is connected. This is
                     applicable only when device_operation_mode is DOM_CLOUD or
                     DOM_CLOUD_WITH_SUPPORT. This won't be available for non
                     Central uses case
        required: False
        type: str
    default_gateway_ip:
        description: The global IPV4 default gateway. Input octets
                     as 0.0.0.0 to reset.
        required: False
        type: str

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
     - name: Updates the given console authorization configuration
             to the system
       arubaoss_system_attributes:
         hostname: "Test_santorini"
         location: "Bangalore"
         contact: "08099035734"
         domain_name: "hpe.com"
         version: "IAV_IP_V4"
         device_operation_mode: "DOM_AUTONOMOUS"
         uplink_vlan_id: "10"
         uplink_ip: "10.100.20.30"
         default_gateway_ip: "10.100.119.1"
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA

"""
-------
Name: config

Configures port with system_attributes config

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config(module):

    params = module.params
    data = {}

    if not params['hostname'] == "":
        data['name'] = params['hostname']

    if not params['location'] == "":
        data['location'] = params['location']

    if not params['contact'] == "":
        data['contact'] = params['contact']

    if not params['domain_name'] == "":
        data['regulatory_domain'] = params['domain_name']

    if not params['uplink_ip'] == "":
        data['uplink_ip_address'] = {'version': params['version'],
                                     'octets': params['uplink_ip']}

    if not params['default_gateway_ip'] == "":
        data['default_gateway'] = {'version': params['version'],
                                   'octets': params['default_gateway_ip']}

    if not params['uplink_vlan_id'] == "":
        data['uplink_vlan_id'] = params['uplink_vlan_id']

    if not params['device_operation_mode'] == "":
        data['device_operation_mode'] = params['device_operation_mode']

    url = '/system'
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
        hostname=dict(type='str', required=False, default=''),
        location=dict(type='str', required=False, default=''),
        contact=dict(type='str', required=False, default=''),
        version=dict(type='str', required=False, default='IAV_IP_V4',
                     choices=['IAV_IP_V4', 'IAV_IP_V6']),
        domain_name=dict(type='str', required=False, default=''),
        device_operation_mode=dict(type='str', required=False,
                                   default='DOM_AUTONOMOUS',
                                   choices=["DOM_CLOUD",
                                            "DOM_CLOUD_WITH_SUPPORT",
                                            "DOM_AUTONOMOUS"]),
        uplink_vlan_id=dict(type='str', required=False, default=''),
        uplink_ip=dict(type='str', required=False, default=''),
        default_gateway_ip=dict(type='str', required=False, default=''),
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
        result = config(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
