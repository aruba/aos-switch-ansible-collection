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
module: arubaoss_lacp

short_description: implements REST API for Lacp

version_added: "1.6.0"

description:
    - "This implements REST APIs which can be used to configure Lacp"

options:
    port_id:
        description: Port ID to be configured
        required: True
        type: str
    trunk_group:
        description: Trunk Group Name
        required: True
        type: str
    lacp:
        description: Specify if the Trunk Group is Lacp or Trunk
        choices: ["True", "False"]
        required: True
        type: str
    state:
        description: Specify if Port needs to be created or Deleted
        choices: ["create", "delete"]
        default: "create"
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
    - Emimal (@hpe)
'''  # NOQA

EXAMPLES = '''
      - name: Resulting config - trunk 1/2 Trk3 lacp
        arubaoss_lacp:
          port_id: 1/2
          trunk_group: trk3
          lacp: True

      - name: Resulting config - trunk 13 Trk20 trunk
        arubaoss_lacp:
          port_id: 13
          trunk_group: trk20
          lacp: False

      - name: Resulting config - trunk A1 Trk20 trunk
        arubaoss_lacp:
          port_id: A1
          trunk_group: Trk20
          lacp: False

      - name: Resulting config - trunk 14 Trk50 lacp
        arubaoss_lacp:
          port_id: 14
          trunk_group: Trk50
          lacp: True

      - name: DELETE remove port from Trk20
        arubaoss_lacp:
          port_id: 15
          trunk_group: Trk20
          lacp: True
          state: delete

      - name: DELETE remove port from Trk50
        arubaoss_lacp:
          port_id: 16
          trunk_group: Trk50
          lacp: True
          state: delete

'''  # NOQA

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA


def config_trunk_port(module):

    params = module.params
    trunk_group = params['trunk_group'].lower()
    port_id = params['port_id'].lower()

    data = {'port_id': params['port_id'],
            'trunk_group': params['trunk_group']}

    # check if the port to be configured is lacp or trunk
    match_port = 'false'
    if module.params['lacp'] == 'True':
        my_trk_url = '/lacp/port'
        my_trk_ele = 'lacp_element'
        other_trk_url = '/trunk/port'
        other_trk_ele = 'trunk_element'
    else:
        my_trk_url = '/trunk/port'
        my_trk_ele = 'trunk_element'
        other_trk_url = '/lacp/port'
        other_trk_ele = 'lacp_element'

    # trunk_element has both lacp and trunk element but lacp has only lacp element \
    # so using trunk_match and port_id_match to find if the lacp port/group is present \
    # in trunk group
    trunk_match = 'False'
    port_id_match = 'False'
    if params['state'] == 'create':
        trk_config = get_config(module, other_trk_url)
        trk_data_other = module.from_json(to_text(trk_config))
        check_config = get_config(module, my_trk_url)
        old_trk_data = module.from_json(to_text(check_config))
    # if the port is configured in lacp group, then checking if lacp port/group is \
    # present in trunk_group and vice versa
        for ele in old_trk_data[my_trk_ele]:
            if ele['trunk_group'].lower() == trunk_group:
                trunk_match = 'True'
            elif ele['port_id'].lower() == port_id:
                port_id_match = 'True'
        for elem in trk_data_other[other_trk_ele]:
            if elem['trunk_group'].lower() == trunk_group and trunk_match == 'False':
                return {'msg': 'Specified trunk type is inconsistent with existing trunk group'}
            elif elem['port_id'].lower == port_id and port_id_match == 'False':
                return {'msg': 'Specified port already belongs to another trunk type'}

    # trunk_element has both lacp and trunk element but lacp has only lacp element \
    # so using my_trunk_match and my_port_id_match to find if the lacp port/group is present \
    # in trunk group
    my_trunk_match = 'False'
    my_port_id_match = 'False'
    check_config = get_config(module, my_trk_url)
    old_trk_data = module.from_json(to_text(check_config))
    trk_config = get_config(module, other_trk_url)
    other_trk_data = module.from_json(to_text(trk_config))
    for element in other_trk_data[other_trk_ele]:
        if element['trunk_group'].lower() == trunk_group and params['state'] == 'create':
            if module.params['lacp'] == 'True':
                my_trunk_match = 'False'
            else:
                my_trunk_match = 'True'
                return {'msg': 'Trunk to be configured is already in use'}
        elif element['port_id'].lower() == port_id and params['state'] == 'create':
            my_port_id_match = 'True'
            return {'msg': 'Port to be configured is already in use'}
    # checking if the lacp port/group to be configured is already configured as \
    # part of lacp port/group
    if old_trk_data:
        for ele in old_trk_data[my_trk_ele]:
            if my_trunk_match == 'False' or my_port_id_match == 'False':
                if ele['trunk_group'].lower() == trunk_group and ele['port_id'].lower() == port_id:
                    match_port = 'true'
                elif ele['port_id'].lower() == port_id and params['state'] == 'create':
                    return {'msg': 'Specified Port belongs to another  trunk group {0}'.format(ele['port_id'].lower()), 'changed': False, 'failed': False}

    # A trunk group can have maximum of 8 ports
    if params['state'] == 'create' and match_port == 'false':
        ports_sme_trunk = 0
        check_config = get_config(module, my_trk_url)
        trk_data = module.from_json(to_text(check_config))
        if trk_data:
            for ele in trk_data[my_trk_ele]:
                if ele['trunk_group'].lower() == trunk_group:
                    ports_sme_trunk += 1
                    if ports_sme_trunk > 7:
                        return {'msg': 'Max ports in same trunk'}

    method = 'POST'
    if params['state'] == 'delete':
        method = 'DELETE'
        my_trk_url = my_trk_url + '/' + str(params['port_id'])

    # if trying to configure already configured port or trying to delete an unconfigured port
    if match_port == 'true':
        if method == 'POST':
            return {'msg': 'Specified trunk port already configured', 'changed': False, 'failed': False}
    else:
        if method == 'DELETE':
            return {'msg': 'Specified trunk port does not exists', 'changed': False, 'failed': False}

    result = run_commands(module, my_trk_url, data, method)

    return result


def run_module():
    module_args = dict(
        port_id=dict(type='str', required=True),
        trunk_group=dict(type='str', required=True),
        lacp=dict(type='str', required=True, choices=['True', 'False']),
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete'])
    )
    module_args.update(arubaoss_argument_spec)

    result = dict(changed=False, warnings='Not Supported')

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    # trying to configure port not present in switch
    port_url = '/ports/' + str(module.params['port_id'])
    check_port = get_config(module, port_url)
    if not check_port:
        result = {'msg': 'Port {0} not present on device {1}'
                  .format(module.params['port_id'], port_url),
                  'changed': False}
    else:
        try:
            result = config_trunk_port(module)

        except Exception as err:
            return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
