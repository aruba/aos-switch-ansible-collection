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
module: arubaoss_syslog

short_description: implements rest api for syslog configuration

version_added: "2.6.0"

description:
    - "This implements rest api's which configure syslog on device"

options:
    server_address:
        description:
            - syslog server IP address
        required: true
        type: str
    version:
        description:
            - Server IP address version
        default: IAV_IP_V4
        choices: [ IAV_IP_V4, IAV_IP_V6 ]
        required: false
        type: str
    description:
        description:
            - Server description
        required: false
        type: str
    protocol:
        description:
            - Type of protocol to configure
        default: TP_UDP
        choices: [ TP_TCP, TP_UDP, TP_TLS ]
        required: false
        type: str
    server_port:
        description:
            - Server port id to be configured
        required: false
        type: int
    state:
        description:
            - Create or delete configuration
        default: create
        choices: [ create, delete ]
        required: false
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
    - Ashish Pant (@hpe)
'''

EXAMPLES = '''
      - name: configure syslog server
        arubaoss_syslog:
          server_address: 1.1.1.1
          protocol: TP_TCP

      - name: delete syslog server
        arubaoss_syslog:
          server_address: 1.1.1.1
          state: delete

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
import sys  # NOQA


def config_syslog(module):

    params = module.params
    url = '/syslog/servers'
    check_url = url + '/' + params['server_address']

    if params['state'] == 'delete':
        result = run_commands(module, check_url,
                              method='DELETE', check=check_url)
        return result
    else:
        check_syslog = get_config(module, check_url)
        if check_syslog:
            method = 'PUT'
            url = check_url
        else:
            method = 'POST'

    data = {
        'ip_address': {
            'octets': params['server_address'],
            'version': params['version']
        },
        'transport_protocol': params['protocol'],
    }

    protocol = params['protocol']
    if params['server_port'] == 0:
        if protocol == 'TP_UDP':
            port = 514
        elif protocol == 'TP_TCP':
            port = 1470
        elif protocol == 'TP_TLS':
            port = 6514
        data.update({'port': port})
    else:
        data.update({'port': params['server_port']})

    if params['description']:
        data.update({'control_description': params['description']})

    result = run_commands(module, url, data, method, check=check_url)

    return result


def run_module():
    module_args = dict(
        server_address=dict(type='str', required=True),
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete']),
        version=dict(type='str', required=False, default='IAV_IP_V4',
                     choices=['IAV_IP_V4', 'IAV_IP_V6']),
        description=dict(type='str', required=False, default=""),
        protocol=dict(type='str', required=False, default='TP_UDP',
                      choices=['TP_UDP', 'TP_TCP', 'TP_TLS']),
        server_port=dict(type='int', required=False, default=0),
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
        result = config_syslog(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
