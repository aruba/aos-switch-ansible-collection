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
module: arubaoss_ip_auth

short_description: implements rest api for ip authorization

version_added: "2.6.0"

description:
    - "This implements rest api's which configure ip autorization on device"

options:
    auth_ip:
        description:
            - Ip address for autherization.
        required: false
        type: str
    access_role:
        description:
            - Type of access to be allowed.
        required: false
        choices: [ AR_MANAGER, AR_OPERATOR ]
        type: str
    mask:
        description:
            - Net mask for auth_ip.
        required: false
        type: str
    access_method:
        description:
            - Type of access method allowed.
        required: false
        choices: [ AM_ALL, AM_SSH, AM_TELNET, AM_WEB, AM_SNMP, AM_TFTP ]
        default: AM_ALL
        type: str
    auth_id:
        description:
            - Sequence number for auth rule
        required: false
        type: int
    state:
        description:
            - Enable/disable/read ip auth data
        required: false
        default: create
        choices: [ create, delete ]
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
      - name: create ip auth all
        arubaoss_ip_auth:
          auth_ip: 10.0.12.91
          mask: 255.255.248.0
          access_role: AR_MANAGER
          access_method: AM_ALL
        register: auth_1

      - name: delete ip auth all
        arubaoss_ip_auth:
          auth_ip: 10.0.12.92
          auth_id: "{{auth_1.id}}"
          state: delete
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA


def ip_auth(module):

    params = module.params
    url = '/ip_auth'

    if params['auth_id']:
        url = url + '/' + str(params['auth_id'])

    if params['state'] == 'create':
        if not params['mask'] or not params['auth_ip']:
            return {'msg': 'Required args: auth_ip, mask', 'changed': False}

        data = {
            'auth_ip': {
                'octets': params['auth_ip'],
                'version': 'IAV_IP_V4'
            },
            'auth_ip_mask': {
                'octets': params['mask'],
                'version': 'IAV_IP_V4',
            },
            'access_role': params['access_role'],
            'access_method': params['access_method']
        }

        if not params['auth_id']:
            auth_check = get_config(module, url)
            if auth_check:
                check_config = module.from_json(to_text(auth_check))
                total = 0
                check = 0

                for ele in check_config['ip_auth_element']:
                    for key in data:
                        if key in ele:
                            if ele[key] != data[key]:
                                check += 1
                                break

                total = \
                    check_config['collection_result']['total_elements_count']
                diff = total - check
                if (total > 1 and diff == 1) or (total == 1 and check == 0):
                    return {'msg': 'Ip auth rule already exists.',
                            'changed': False}

            result = run_commands(module, url, data, 'POST')
        else:
            result = run_commands(module, url, data, 'PUT', check=url)

    else:
        if not params['auth_id']:
            return {'msg': 'auth_id is required for deletion',
                    'changed': False}

        result = run_commands(module, url, {}, 'DELETE', check=url)

    return result


def run_module():
    module_args = dict(
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete']),
        auth_ip=dict(type='str', required=False),
        access_role=dict(type='str', required=False,
                         choices=['AR_MANAGER', 'AR_OPERATOR']),
        mask=dict(type='str', required=False),
        access_method=dict(type='str', required=False, default='AM_ALL',
                           choices=['AM_ALL', 'AM_SSH', 'AM_TELNET',
                                    'AM_WEB', 'AM_SNMP', 'AM_TFTP']),
        auth_id=dict(type='int', required=False),
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
        result = ip_auth(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
