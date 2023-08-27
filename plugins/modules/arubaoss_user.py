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
module: arubaoss_user

short_description: Implements Ansible module for configuring and
                   managing user on device.

version_added: "2.6.0"

description:
    - "This implement rest api's which can be use to manage and configure
       user on the device. Can configure only operator role via REST"

options:
    user_name:
        description:
            - user_name that needs to be configured.
        required: true
        type: str
    user_type:
        description:
            - Type of user being configured.
        required: false
        choices: [ UT_OPERATOR, UT_MANAGER ]
        default: UT_OPERATOR
        type: str
    user_password:
        description:
            - user password in plain text or sha1
        required: true
        type: str
    password_type:
        description:
            - type of password being conifgured
        required: false
        choices: [ PET_PLAIN_TEXT, PET_SHA1 ]
        default: PET_PLAIN_TEXT
        type: str
    state:
        description:
            - Enable or disable
        choices: [ create, delete ]
        default: create
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
      - name: configure user
        arubaoss_user:
          user_name:  test_user
          user_password: test_user
          user_type: UT_OPERATOR
          password_type: PET_PLAIN_TEXT

      - name: delete user
        arubaoss_user:
          user_name:  test_user
          user_password: test_user
          user_type: UT_OPERATOR
          password_type: PET_PLAIN_TEXT
          state: delete

      - name: configure user sha1
        arubaoss_user:
          user_name: test_user
          user_password: F0347CE3A03A3BA71F596438A2B80DD21C9AF71B
          user_type: UT_OPERATOR
          password_type: PET_SHA1

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA


def config_user(module):

    params = module.params
    url = '/management-user'

    if params['state'] == 'create':
        for key in ['user_password', 'password_type', 'user_name']:
            if key not in params:
                return {'msg': '{0} is mandatory to create user'.format(key),
                        'changed': False, 'failed': True}

    data = {
        'type': params['user_type'],
        'name': params['user_name'],
        'password': params['user_password'],
        'password_type': params['password_type']
    }

    method = 'POST'
    delete_url = url + '/' + params['user_type']
    get_user = get_config(module, delete_url)
    if get_user:
        if params['state'] == 'delete':
            method = 'DELETE'
        else:
            method = 'PUT'
        url = delete_url

    if params['state'] == 'create':
        inc_url = '/system/include-credentials'
        check_presence = get_config(module, inc_url)
        check_presence = module.from_json(to_text(check_presence))

        if check_presence:
            inc_url = '/system/include-credentials'
            if check_presence['include_credentials_in_response'] == \
                    'ICS_DISABLED' and params['password_type'] == 'PET_SHA1':
                inc_data = \
                    {'include_credentials_in_response': 'ICS_ENABLED'}
                run_commands(module, inc_url, inc_data,
                             'PUT', wait_after_send=5)

            elif check_presence['include_credentials_in_response'] != \
                    'ICS_DISABLED' and \
                    params['password_type'] == 'PET_PLAIN_TEXT':
                inc_data = \
                    {'include_credentials_in_response': 'ICS_DISABLED'}
                run_commands(module, inc_url, inc_data,
                             'PUT', wait_after_send=5)

    result = run_commands(module, url, data, method)
    return result


def run_module():
    module_args = dict(
        user_name=dict(type='str', required=True, no_log=True),
        user_type=dict(type='str', required=False, default='UT_OPERATOR',
                       choices=['UT_OPERATOR', 'UT_MANAGER']),
        user_password=dict(type='str', required=True, no_log=True),
        password_type=dict(type='str', required=False,
                           default='PET_PLAIN_TEXT',
                           choices=['PET_PLAIN_TEXT', 'PET_SHA1']),
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete']),
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
        result = config_user(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
