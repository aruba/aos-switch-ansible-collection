#!/usr/bin/python
#
# Copyright (c) 2019-2020 Hewlett Packard Enterprise Development LP
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
module: arubaoss_dsnoop

short_description: implements REST API for DHCP snooping

version_added: "2.4"

description:
    - "This implements REST APIs which can be used to configure DHCP snooping"

options:
    command:
        description: To configure a specific feature on DHCP snooping
        choices: ["authorized_server","option_82", "dsnoop"]
        required: False
        default: "dsnoop"
    dsnoop:
        description: To enable or disable DHCP snooping.
        choices: [True, False]
        required: False
        default: False
    is_dsnoop_option82_enabled:
        description: To enable/disable adding option 82 relay information to DHCP client
                     packets that are forwarded on trusted ports
        choices: [True, False]
        required: False
        default: True
    remote_id:
        description: To select the address used as the Remote ID for option 82
        choices: ["DRI_MAC","DRI_SUBNET_IP", "DRI_MGMT_IP"]
        required: False
        default: "DRI_MAC"
    untrusted_policy:
        description: To set the policy for DHCP packets containing option 82 that are
                     received on untrusted ports
        choices: ["DUP_DROP","DUP_KEEP", "DUP_REPLACE"]
        required: False
        default: "DUP_DROP"
    server_ip:
        description: Add an authorized DHCP server address.
        required: False
        default: ""
    config:
        description: To configure or unconfigure the required command
        choices: ["create", "delete"]
        default: "create"

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
    - Sunil Veeramachaneni (@hpe)
'''  # NOQA

EXAMPLES = '''
      - name: enable dsnoop
        arubaoss_dsnoop:
          dsnoop: true

      - name: disable dsnoop
        arubaoss_dsnoop:
          dsnoop: false

      - name: enable dsnoop option82 with untrusted-policy keep remote-id subnet-ip
        arubaoss_dsnoop:
          command: option_82
          is_dsnoop_option82_enabled: true
          remote_id: "DRI_SUBNET_IP"
          untrusted_policy: "DUP_KEEP"

      - name: disable dsnoop option82
        arubaoss_dsnoop:
          command: option_82
          is_dsnoop_option82_enabled: false

      - name: add dsnoop authorized_server
        arubaoss_dsnoop:
          command: authorized_server
          server_ip: "30.0.0.1"

      - name: remove dsnoop authorized_server
        arubaoss_dsnoop:
          command: authorized_server
          server_ip: "30.0.0.1"
          config: "delete"
'''  # NOQA

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA


def config(module):
    """
    -------
    Name: config

    Configures port with system_attributes config

    param request: module

    Returns
     Configure the switch with params sent
    -------
    """
    params = module.params
    data = {'is_dhcp_snooping_enabled': params['dsnoop']}
    url = '/dsnoop'
    method = 'PUT'
    result = run_commands(module, url, data, method, check=url)

    return result


def option_82(module):
    """
    -------
    Name: option_82

    Configures DHCP Snooping option 82

    param request: module

    Returns
     Configure the switch with params sent
    -------
    """
    params = module.params
    url = '/dsnoop/option_82'

    data = {'is_dsnoop_option82_enabled': params['is_dsnoop_option82_enabled']}
    data['remote_id'] = params['remote_id']
    data['untrusted_policy'] = params['untrusted_policy']

    method = 'PUT'
    result = run_commands(module, url, data, method, check=url)

    return result


def authorized_server(module):
    """
    -------
    Name: authorized_server

    Configures DHCP Snooping authorized server

    param request: module

    Returns
     Configure the switch with params sent
    -------
    """
    params = module.params
    url = '/dsnoop/authorized_server'

    data = {'is_dsnoop_option82_enabled': params['is_dsnoop_option82_enabled']}
    data['authorized_server'] = {"version": "IAV_IP_V4",
                                 "octets": params['server_ip']}

    method = 'POST'
    if params['config'] == 'delete':
        method = 'DELETE'
        url = url + '/' + params['server_ip']

    result = run_commands(module, url, data, method)

    return result


def run_module():
    """
    -------
    Name: run_module()

    The main module invoked

    Returns
     Configure the switch with params sent
    -------
    """
    module_args = dict(
        command=dict(type='str', required=False, default="dsnoop",
                     choices=["authorized_server",
                              "option_82",
                              "dsnoop"]),
        dsnoop=dict(type='bool', required=False, default=False),
        is_dsnoop_option82_enabled=dict(type='bool', required=False,
                                        default=True),
        remote_id=dict(type='str', required=False, default="DRI_MAC",
                       choices=["DRI_MAC", "DRI_SUBNET_IP", "DRI_MGMT_IP"]),
        untrusted_policy=dict(type='str', required=False, default="DUP_DROP",
                              choices=["DUP_DROP", "DUP_KEEP", "DUP_REPLACE"]),
        server_ip=dict(type='str', required=False, default=""),
        config=dict(type='str', required=False, default="create",
                    choices=["create", "delete"]),
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
        if module.params['command'] == "authorized_server":
            result = authorized_server(module)
        elif module.params['command'] == "option_82":
            result = option_82(module)
        else:
            result = config(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
