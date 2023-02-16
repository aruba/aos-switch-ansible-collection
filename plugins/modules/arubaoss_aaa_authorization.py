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
module: arubaoss_aaa_authorization

short_description: implements rest api for AAA Authorization configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure authorization"

options:
    command:
        description: To configure a specific feature on AAA authorization
        choices: ["authorization_group", "authorization_method"]
        required: False
        default: "authorization_method"
        type: 'str'
    authorization_method:
        description: To authorization method needed
        choices: ["AZM_NONE", "AZM_TACACS"]
        default: "AZM_NONE"
        required: False
        type: 'str'
    group_name:
        description: Group name for the autorization group
        default: ''
        type: 'str'
    seq_num:
        description: The sequence number. <1-2147483647>
        default: 0
        type: 'int'
    match_cmd:
        description: Specify the command to match.
        default: ''
        type: 'str'
    cmd_permission:
        description: Permit or deny the match command
        choices: ["AZP_PERMIT","AZP_DENY"]
        required: False
        default: "AZP_PERMIT"
        type: 'str'
    is_log_enabled:
        description: Generate an event log any time a match happens.
        required: False
        default: False
        type: 'bool'
    config:
        description: To config or unconfig the required command
        choices: ["create", "delete"]
        default: "create"
        type: 'str'
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
     - name: Updates the given console authorization
             configuration to the system
       arubaoss_aaa_authorization:
         authorization_method: "AZM_TACACS"

     - name: Create Authorization group
       arubaoss_aaa_authorization:
         command: authorization_group
         group_name: "cool"
         seq_num: 500
         match_cmd: "show running-config"
         cmd_permission: "AZP_PERMIT"
         is_log_enabled: "true"

     - name: Create Authorization group
       arubaoss_aaa_authorization:
         command: authorization_group
         group_name: "cool"
         seq_num: 600
         match_cmd: "show version"
         cmd_permission: "AZP_DENY"
         is_log_enabled: "false"

     - name: Delete Authorization group
       arubaoss_aaa_authorization:
         command: authorization_group
         group_name: "cool"
         seq_num: 500
         config: "delete"
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    returned: always
    type: str
message:
    description: The output message that the sample module generates
    returned: always
    type: str
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA


"""
-------
Name: config

Configures port with authorization config

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config(module):

    params = module.params
    data = {'authorization_method': params['authorization_method']}
    url = '/authorization'
    method = 'PUT'
    result = run_commands(module, url, data, method, check=url)

    return result


"""
-------
Name: authorization_group()

Configure the authorization group

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authorization_group(module):
    params = module.params
    data = {}

    # URI
    url = "/authorization_group"
    get_url = url + "/" + params['group_name'] + "-" + str(params['seq_num'])

    if params['config'] == "create":
        method = "POST"
    else:
        method = "DELETE"
        url = get_url

    data['group_name'] = params['group_name']
    data['seq_num'] = params['seq_num']

    if method == "POST":
        if params['match_cmd'] != "":
            data['match_cmd'] = '\"' + params['match_cmd'] + '\"'
        else:
            data['match_cmd'] = ""

        data['cmd_permission'] = params['cmd_permission']
        data['is_log_enabled'] = params['is_log_enabled']

    check_presence = get_config(module, get_url)
    if check_presence:
        # Sequence exists
        if method == "POST":
            return {'msg': 'The sequence exists.',
                    'changed': False, 'failed': False}
    else:
        # Sequence does not exist
        if method == "DELETE":
            return {'msg': 'The sequence does not exist.',
                    'changed': False, 'failed': False}

    # Config
    result = run_commands(module, url, data, method)
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
                     default="authorization_method",
                     choices=["authorization_group",
                              "authorization_method"]),
        authorization_method=dict(type='str', required=False,
                                  default="AZM_NONE",
                                  choices=["AZM_NONE", "AZM_TACACS"]),
        group_name=dict(type='str', required=False, default=""),
        seq_num=dict(type='int', required=False, default=0),
        match_cmd=dict(type='str', required=False, default=""),
        cmd_permission=dict(type='str', required=False, default="AZP_PERMIT",
                            choices=["AZP_PERMIT", "AZP_DENY"]),
        is_log_enabled=dict(type='bool', required=False, default=False),
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
        if module.params['command'] == "authorization_group":
            result = authorization_group(module)
        else:
            result = config(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
