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
module: arubaoss_tacacs_profile

short_description: implements rest api for TACACS configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure TACACS Server"

options:
  command:
    description: Function name calls according to configuration required.
      choice config_tacacs_server - Configure a TACACS+ server.
      choice config_tacacs_profile - Configure global TACACS+ profile.
    choices: [ config_tacacs_profile, config_tacacs_server ]
    required: True
  config:
    description: To configure or unconfigure the required command.
    choices: [ create, delete ]
    default: create
    required: False
  dead_time:
    description: Dead time for unavailable TACACS+ servers. Used with the
                 config_tacacs_profile command.
    type: int
    default: 0
    required: False
  time_out:
    description: TACACS server response timeout. Used with the
                 config_tacacs_profile command.
    type: int
    default: 5
    required: False
  global_auth_key:
    description: Configure the default authentication key for all
                 TACACS+ servers. Used with the config_tacacs_profile
                 command. To delete, pass in empty string ''.
    required: False
    type: str
  ip_address:
    description: TACACS Server IP Address. Used with the
                 config_tacacs_server command.
    required: False
    type: str
  auth_key:
    description: Configure the server authentication key. Used with the
                 config_tacacs_server command.
    required: False
    type: str
  is_oobm:
    description: Use oobm interface to connect the server. Used with the
                 config_tacacs_server
    default: False
    type: bool
    required: False
  ordering_sequence:
    description: Enables reordering upon deletion of existing server.
                 Used with the config_tacacs_profile command.
    required: False
    type: bool
    default: False

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
- name: Creates tacacs-server host 10.1.1.1 with key Aruba!
  arubaoss_tacacs_profile:
    command: config_tacacs_server
    ip_address: 10.1.1.1
    auth_key: "Aruba!"
    is_oobm: true

- name: Deletes tacacs-server host 10.1.1.1 with key Aruba!
  arubaoss_tacacs_profile:
    command: config_tacacs_server
    ip_address: 10.1.1.1
    auth_key: "Aruba!"
    config: delete

- name: Creates global TACACS+ authentication key
  arubaoss_tacacs_profile:
    command: config_tacacs_profile
    global_auth_key: "Aruba!"

- name: Configure global TACACS+ settings
  arubaoss_tacacs_profile:
    command: config_tacacs_profile
    global_auth_key: "Aruba!"
    dead_time: 60
    time_out: 10

- name: Deletes Global TACACS+ settings
  arubaoss_tacacs_profile:
    command: config_tacacs_profile
    global_auth_key: ""
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA

"""
-------
Name: config_tacacs_profile

Configures port with tacacs profile config

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config_tacacs_profile(module):

    params = module.params

    data = {}

    data['dead_time'] = params['dead_time']
    data['time_out'] = params['time_out']
    data['global_auth_key'] = params['global_auth_key']
    data['ordering_sequence'] = params['ordering_sequence']

    url = '/tacacs_profile'

    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: config_tacacs_server

Configures port with tacas server

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config_tacacs_server(module):

    params = module.params

    data = {}
    if params['ip_address'] == "" or params['version'] == "":
        return {'msg': "IP Address or version cannot be null",
                'changed': False, 'failed': False}
    else:
        data["server_ip"] = {"version": params['version'],
                             "octets": params['ip_address']}

    data["auth_key"] = params['auth_key']
    data["is_oobm"] = params['is_oobm']

    create_url = '/tacacs_profile/server'
    check_url = '/tacacs_profile/server/' + str(params['ip_address'])

    if params['config'] == "create":
        check_presence = get_config(module, '/tacacs_profile/server/'
                                    + str(params['ip_address']))
        if not check_presence:
            url = create_url
            method = 'POST'
        else:
            url = check_url
            method = 'PUT'
    else:
        url = check_url
        method = 'DELETE'

    result = run_commands(module, url, data, method, check=check_url)
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
                     default="config_tacacs_profile",
                     choices=["config_tacacs_profile",
                              "config_tacacs_server"]),
        config=dict(type='str', required=False, default="create",
                    choices=["create", "delete"]),
        dead_time=dict(type='int', required=False, default=0),
        time_out=dict(type='int', required=False, default=5),
        ordering_sequence=dict(type='bool', required=False, default=False),
        global_auth_key=dict(type='str', required=False, default=""),
        auth_key=dict(type='str', required=False, default=""),
        ip_address=dict(type='str', required=False, default=""),
        version=dict(type='str', required=False, default="IAV_IP_V4"),
        is_oobm=dict(type='bool', required=False, default=False),
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
        if module.params['command'] == "config_tacacs_profile":
            result = config_tacacs_profile(module)
        else:
            result = config_tacacs_server(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
