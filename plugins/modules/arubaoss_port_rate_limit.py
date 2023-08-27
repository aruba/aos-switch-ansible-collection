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
module: arubaoss_port_rate_limit

short_description: implements rest api for AAA Accounting configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure AAA Accounting"

options:
    command:
        description: Function name calls according to configuration required
        choices: [ update_rate_limit_attributes,
                 clear_rate_limit_trap,
                 update_rate_limit_onPort,
                 update_rate_limit_attributes_onPort ]
        required: False
        default: update_rate_limit_attributes
        type: str
    port_id:
        description: Port_id of the port
        required: False
        type: str
    icmp_traffic_type:
        description: ICMP traffic type.
        choices: [ PITT_IP_ALL, PITT_IP_V4, PITT_IP_V6 ]
        required: False
        default: PITT_IP_V4
        type: str
    queues_direction:
        description: Queue traffic direction. port_id and queues_direction
                     are required to uniquely identify the
                     queue_rate_percentage to be set
        choices: [ PQTD_OUT ]
        required: False
        default: PQTD_OUT
        type: str
    queue_rate_percentage_1:
        description: Rate limit for egress queue 1 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_2:
        description: Rate limit for egress queue 2 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_3:
        description: Rate limit for egress queue 3 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_4:
        description: Rate limit for egress queue 4 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_5:
        description: Rate limit for egress queue 5 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_6:
        description: Rate limit for egress queue 6 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_7:
        description: Rate limit for egress queue 8 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    queue_rate_percentage_8:
        description: Rate limit for egress queue 8 in percentage. Apply
                     the default value on all queues to reset the configuration
        required: False
        default: 100
        type: int
    traffic_type:
        description: The traffic type. port_id, traffic_type and
                     direction are  required to uniquely identify
                     the rate_limit value to be set
        choices: [ PTT_BCAST, PTT_MCAST, PTT_ALL, PTT_UKWN_UNCST ]
        required: False
        default : PTT_ALL
        type: str
    direction:
        description: Traffic flow direction. port_id, traffic_type and
                     direction are required to uniquely identify the
                     rate_limit value to be set. PTD_OUT is applicable,
                     only when traffic_type is PTT_ALL on
                     specific platforms
        choices: [ PTD_IN, PTD_OUT ]
        required: False
        default: PTD_IN
        type: str
    rate_limit:
        description: Rate limit value. rate_limit_in_kbps and
                     rate_limit_in_percent will be null if rate_limit
                     is not configured
        required: False
        default: ''
        type: str
    rate_limit_in_kbps:
        description: Rate limit in kbps
        required: False
        default: 0
        type: int
    rate_limit_in_percent:
        description: Rate limit in percentage
        required: False
        default: 0
        type: int
    config:
        description: Create or Delete Port Rate Limit
        choices: ['create', 'delete']
        default: create
        type: str
        required: False

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
     - name: Updates attributes of port ICMP rate limit per port id
       arubaoss_port_rate_limit:
         command: update_rate_limit_attributes
         port_id: 1
         icmp_traffic_type: "PITT_IP_ALL"
         rate_limit_in_kbps: "10"
         rate_limit_in_percent: "0"

'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The output message that the sample module generates
    type: str
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA
import sys  # NOQA
import json  # NOQA

"""
-------
Name: update_rate_limit_attributes

Updates attributes of port ICMP rate limit per port id

param request: module

Returns
 Configure the switch with params sent
-------
"""


def update_rate_limit_attributes(module):

    params = module.params

    data = {}
    data['icmp_rate_limit'] = {'rate_limit_in_percent': 10}

    data['port_id'] = params['port_id']
    data['icmp_traffic_type'] = params['icmp_traffic_type']

    # Rate limit should be in kbps or percent
    if params['rate_limit_in_kbps'] == 0:
        data['icmp_rate_limit'] = \
            {'rate_limit_in_percent': params['rate_limit_in_percent']}
    else:
        data['icmp_rate_limit'] = \
            {'rate_limit_in_kbps': params['rate_limit_in_kbps']}

    url = '/ports/icmp_rate_limit/' + str(params['port_id'])
    method = 'PUT'

    # Idempotency check: Check if already configured
    diffSeen = False
    check_presence = get_config(module, url)
    newdata = json.loads(check_presence)
    for key in data:
        if not newdata[key] == data[key]:
            diffSeen = True
            if key == "icmp_rate_limit":
                if params['rate_limit_in_kbps'] == 0 and \
                        newdata[key]['rate_limit_in_kbps'] is None:
                    diffSeen = False
                if params['rate_limit_in_percent'] == 0 and \
                        newdata[key]['rate_limit_in_percent'] is None:
                    diffSeen = False
            break
    if diffSeen:
        result = run_commands(module, url, data, method)
        return result
    else:
        return {'msg': 'Already configured',
                'changed': False, 'failed': False}


"""
-------
Name: clear_rate_limit_trap

Trap-clear for ICMP rate-limit on a port.

param request: module

Returns
 Configure the switch with params sent
-------
"""


def clear_rate_limit_trap(module):

    params = module.params

    data = {}
    data['port_id'] = params['port_id']
    data['icmp_traffic_type'] = params['icmp_traffic_type']

    url = '/ports/icmp_rate_limit_trap_clear/' + str(params['port_id'])
    method = 'POST'

    result = run_commands(module, url, data, method)
    return result


"""
-------
Name: update_rate_limit_onPort

Updates attributes of port ICMP rate limit per port id

param request: module

Returns
 Configure the switch with params sent
-------
"""


def update_rate_limit_onPort(module):

    params = module.params

    data = {}

    data['queues_direction'] = params['queues_direction']
    data['port_id'] = params['port_id']

    data['queue_rate_percentage'] = [
        params['queue_rate_percentage_1'],
        params['queue_rate_percentage_2'],
        params['queue_rate_percentage_3'],
        params['queue_rate_percentage_4'],
        params['queue_rate_percentage_5'],
        params['queue_rate_percentage_6'],
        params['queue_rate_percentage_7'],
        params['queue_rate_percentage_8']]

    url = '/ports/queues_rate_limit/' + str(params['port_id']) + "-" \
        + str(params['queues_direction'])
    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)

    return result


"""
-------
Name: update_rate_limit_attributes_onPort

Updates attributes of port rate limit per port id, traffic type and direction

param request: module

Returns
 Configure the switch with params sent
-------
"""


def update_rate_limit_attributes_onPort(module):

    params = module.params

    data = {}
    data['port_id'] = params['port_id']
    data['traffic_type'] = params['traffic_type']
    data['direction'] = params['direction']
    data['rate_limit'] = params['rate_limit']

    # Rate limit should be in kbps or percent
    if params['rate_limit_in_kbps'] == 0:
        data['rate_limit'] = \
            {'rate_limit_in_percent': params['rate_limit_in_percent']}
    else:
        data['rate_limit'] = \
            {'rate_limit_in_kbps': params['rate_limit_in_kbps']}

    url = '/ports/rate_limit/' + str(params['port_id']) + "-" \
        + str(params['traffic_type']) + "-" + str(params['direction'])
    method = 'PUT'

    # Idempotency check: Check if already configured
    diffSeen = False
    check_presence = get_config(module, url)
    newdata = json.loads(check_presence)
    for key in data:
        if not newdata[key] == data[key]:
            diffSeen = True
            if params['rate_limit_in_percent'] == 0 and \
                    newdata[key]['rate_limit_in_percent'] is None:
                diffSeen = False
            if params['rate_limit_in_kbps'] == 0 and \
                    newdata[key]['rate_limit_in_kbps'] is None:
                diffSeen = False
            break

    if diffSeen:
        result = run_commands(module, url, data, method)
        return result
    else:
        return {'msg': 'Already configured',
                'changed': False, 'failed': False}


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
                     default='update_rate_limit_attributes',
                     choices=["update_rate_limit_attributes",
                              "clear_rate_limit_trap",
                              "update_rate_limit_onPort",
                              "update_rate_limit_attributes_onPort"]),
        config=dict(type='str', required=False, default='create',
                    choices=["create", "delete"]),
        port_id=dict(type='str', required=False),
        icmp_traffic_type=dict(type='str', required=False,
                               default="PITT_IP_V4",
                               choices=["PITT_IP_ALL",
                                        "PITT_IP_V4",
                                        "PITT_IP_V6"]),
        rate_limit_in_kbps=dict(type='int', required=False, default=0),
        rate_limit_in_percent=dict(type='int', required=False, default=0),
        queues_direction=dict(type='str', required=False, default="PQTD_OUT",
                              choices=["PQTD_OUT"]),
        queue_rate_percentage_1=dict(type='int', required=False, default=100),
        queue_rate_percentage_2=dict(type='int', required=False, default=100),
        queue_rate_percentage_3=dict(type='int', required=False, default=100),
        queue_rate_percentage_4=dict(type='int', required=False, default=100),
        queue_rate_percentage_5=dict(type='int', required=False, default=100),
        queue_rate_percentage_6=dict(type='int', required=False, default=100),
        queue_rate_percentage_7=dict(type='int', required=False, default=100),
        queue_rate_percentage_8=dict(type='int', required=False, default=100),
        traffic_type=dict(type='str', required=False, default="PTT_ALL",
                          choices=["PTT_BCAST", "PTT_MCAST",
                                   "PTT_ALL", "PTT_UKWN_UNCST"]),
        direction=dict(type='str', required=False, default="PTD_IN",
                       choices=["PTD_IN", "PTD_OUT"]),
        rate_limit=dict(type='str', required=False, default=""),
    )

    module_args.update(arubaoss_argument_spec)

    result = dict(changed=False)

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        return result

    try:
        if module.params['command'] == "update_rate_limit_attributes":
            result = update_rate_limit_attributes(module)
        elif module.params['command'] == "clear_rate_limit_trap":
            result = clear_rate_limit_trap(module)
        elif module.params['command'] == "update_rate_limit_onPort":
            result = update_rate_limit_onPort(module)
        else:
            result = update_rate_limit_attributes_onPort(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
