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
module: arubaoss_dot1x

short_description: implements rest api for DOT1x configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure DOT1x"

options:
    command:
        description: Module to be configured.
        choices: [ dot1x_config,
                 authenticator_port_config,
                 authentication_method_config,
                 dot1x_port_security,
                 authenticator_port_clearstats,
                 authenticator_port_initialize,
                 authenticator_port_reauthenticate ]
        required: False
        type: str
        default: 'dot1x_config'
    is_dot1x_enabled:
        description: Global 802.1x admin status
        required: False
        type: bool
        default: False
    cached_reauth_delay:
        description: Global 802.1x cached reauth delay
        required: False
        default: 0
        type: int
    allow_gvrp_vlans:
        description:  allow GVRP vlans
        required: False
        type: bool
        default: False
    use_lldp_data:
        description: Use LLDP data
        required: False
        type: bool
        default: False
    port_id:
        description: Port ID
        required: False
        default: ''
        type: str
    is_authenticator_enabled:
        description: 802.1X Authenticator Port admin status
        required: False
        type: bool
        default: False
    control:
        description: 802.1X Authenticator Port operational control
        required: False
        choices: [ DAPC_UNAUTHORIZED, DAPC_AUTO, DAPC_AUTHORIZED ]
        type: str
        default: DAPC_AUTO
    unauthorized_vlan_id:
        description: 802.1X unauthorized VLAN ID. Displays 0 if not
                     configured. Use 0 to reset unauthorized_vlan_id.
        required: False
        default: 0
        type: int
    client_limit:
        description: Client limit
        required: False
        default: 0
        type: int
    quiet_period:
        description: Quiet Period
        required: False
        default: 0
        type: int
    tx_period:
        description: Tx Period
        required: False
        default: 0
        type: int
    supplicant_timeout:
        description: Supplicant timeout
        required: False
        default: 0
        type: int
    server_timeout:
        description: Server timeout
        required: False
        default: 0
        type: int
    max_requests:
        description: Max requests
        required: False
        default: 0
        type: int
    reauth_period:
        description: Reauth Period
        required: False
        default: 0
        type: int
    authorized_vlan_id:
        description: 802.1X authorized VLAN ID. Displays 0 if not configured.
                     Use 0 to reset authorized_vlan_id
        required: False
        default: 0
        type: int
    logoff_period:
        description: Logoff Period
        required: False
        default: 0
        type: int
    unauth_period:
        description: Unauth period
        required: False
        default: 0
        type: int
    cached_reauth_period:
        description: Cached reauth period
        required: False
        default: 0
        type: int
    enforce_cache_reauth:
        description: Authenticator enforce canched reauthentication
        required: False
        type: bool
        default: False
    primary_authentication_method:
        description: The primary authentication method
        choices: [ DPAM_LOCAL, DPAM_EAP_RADIUS, DPAM_CHAP_RADIUS ]
        required: False
        type: str
        default: DPAM_LOCAL
    secondary_authentication_method:
        description: The secondary authentication method
        choices: [ DSAM_NONE, DSAM_AUTHORIZED, DSAM_CACHED_REAUTH ]
        required: False
        type: str
        default: 'DSAM_NONE'
    server_group:
        description: The server group
        required: False
        default: ''
        type: str
    controlled_direction:
        description: Traffic Controlled direction
        choices: [ DCD_BOTH, DCD_IN ]
        required: False
        type: str
        default: 'DCD_BOTH'
    allow_mbv:
        description: Configuration of MAC based Vlans
        required: False
        type: bool
        default: False
    allow_mixed_users:
        description: Allowed users
        required: False
        type: bool
        default: False
    is_port_speed_vsa_enabled:
        description: Is port speed VSA enabled
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
     - name: Updates the given console dot1x configuration to the system
       arubaoss_aaa_dot1x:
         server_group: "AZM_TACACS"
'''

import json  # NOQA
from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA


"""
-------
Name: dot1x_config

Updates the given 802.1X Port security in the model

param request: module

Returns
 Configure the switch with params sent
-------
"""


def dot1x_config(module):

    params = module.params
    data = {}

    data['is_dot1x_enabled'] = params['is_dot1x_enabled']
    data['cached_reauth_delay'] = params['cached_reauth_delay']
    data['allow_gvrp_vlans'] = params['allow_gvrp_vlans']
    data['use_lldp_data'] = params['use_lldp_data']

    url = '/dot1x'
    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: authenticator_port_config

Updates the given 802.1X Authenticator Port in the model

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authenticator_port_config(module):

    params = module.params

    data = {}
    data['port_id'] = params['port_id']
    if params['port_id'] == "":
        return {'msg': 'Port_id cannot be null',
                'changed': False, 'failed': False}

    data['is_authenticator_enabled'] = params['is_authenticator_enabled']
    data['control'] = params['control']
    data['unauthorized_vlan_id'] = params['unauthorized_vlan_id']
    data['client_limit'] = params['client_limit']
    data['quiet_period'] = params['quiet_period']
    data['tx_period'] = params['tx_period']
    data['supplicant_timeout'] = params['supplicant_timeout']
    data['server_timeout'] = params['server_timeout']
    data['max_requests'] = params['max_requests']
    data['reauth_period'] = params['reauth_period']
    data['authorized_vlan_id'] = params['authorized_vlan_id']
    data['logoff_period'] = params['logoff_period']
    data['unauth_period'] = params['unauth_period']
    data['cached_reauth_period'] = params['cached_reauth_period']
    data['enforce_cache_reauth'] = params['enforce_cache_reauth']

    url = '/dot1x/authenticator/' + params['port_id']
    method = 'PUT'

    # Check if authentication is enabled
    check_presence = get_config(module, "/dot1x")
    if check_presence:
        newdata = json.loads(check_presence)
        if not newdata["is_dot1x_enabled"]:
            return {'msg': 'Cannot enable port authentication '
                    'unless dot1x is enabled',
                    'changed': False, 'failed': False}

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: authentication_method_config

Configures port with dot1x authentication method

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authentication_method_config(module):

    params = module.params
    data = {'server_group': params['server_group']}
    data['primary_authentication_method'] = \
        params['primary_authentication_method']
    data['secondary_authentication_method'] = \
        params['secondary_authentication_method']

    url = '/dot1x/authentication_method'
    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: dot1x_port_security

Updates the given 802.1X Port security in the model

param request: module

Returns
 Configure the switch with params sent
-------
"""


def dot1x_port_security(module):

    params = module.params
    data = {}
    data['port_id'] = params['port_id']
    if params['port_id'] == "":
        return {'msg': 'Port_id cannot be null',
                'changed': False, 'failed': False}
    data['is_port_speed_vsa_enabled'] = params['is_port_speed_vsa_enabled']
    data['allow_mbv'] = params['allow_mbv']
    data['controlled_direction'] = params['controlled_direction']
    data['allow_mixed_users'] = params['allow_mixed_users']

    url = '/dot1x/port_security/' + params['port_id']
    method = 'PUT'

    # Check if authentication is enabled
    check_presence = get_config(module, "/dot1x")
    if check_presence:
        newdata = json.loads(check_presence)
        if not newdata["is_dot1x_enabled"]:
            return {'msg': 'Cannot enable port security unless '
                    'dot1x is enabled',
                    'changed': False, 'failed': False}

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: authenticator_port_initialize

Initialize of dot1x authenticator based on port id

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authenticator_port_initialize(module):

    params = module.params
    data = {}
    data['port_id'] = params['port_id']
    if params['port_id'] == "":
        return {'msg': 'Port_id cannot be null',
                'changed': False, 'failed': False}

    url = '/dot1x/authenticator/' + str(params['port_id']) + '/initialize'
    method = 'POST'

    # Check if authentication is enabled
    check_presence = get_config(module, "/dot1x")
    if check_presence:
        newdata = json.loads(check_presence)
        if not newdata["is_dot1x_enabled"]:
            return {'msg': 'Cannot intialise port unless dot1x is enabled',
                    'changed': False, 'failed': False}

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: authenticator_port_reauthenticate

Reauthenticate of dot1x authenticator based on port id

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authenticator_port_reauthenticate(module):

    params = module.params
    data = {}
    data['port_id'] = params['port_id']
    if params['port_id'] == "":
        return {'msg': 'Port_id cannot be null',
                'changed': False, 'failed': False}

    url = '/dot1x/authenticator/' + params['port_id'] + '/reauthenticate'
    method = 'POST'

    # Check if authentication is enabled
    check_presence = get_config(module, "/dot1x")
    if check_presence:
        newdata = json.loads(check_presence)
        if not newdata["is_dot1x_enabled"]:
            return {'msg': 'Cannot reauthenticate port unless '
                    'dot1x is enabled',
                    'changed': False, 'failed': False}

    result = run_commands(module, url, data, method, check=url)
    return result


"""
-------
Name: authenticator_port_clearstats

Clear statistics of dot1x authenticator based on port id

param request: module

Returns
 Configure the switch with params sent
-------
"""


def authenticator_port_clearstats(module):

    params = module.params
    data = {}
    data['port_id'] = params['port_id']
    if params['port_id'] == "":
        return {'msg': 'Port_id cannot be null',
                'changed': False, 'failed': False}

    url = '/dot1x/authenticator/' + params['port_id'] + '/clearstats'
    method = 'POST'

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
        command=dict(type='str', required=False, default="dot1x_config",
                     choices=['dot1x_config', 'authenticator_port_config',
                              'authentication_method_config',
                              'dot1x_port_security',
                              'authenticator_port_clearstats',
                              'authenticator_port_reauthenticate',
                              'authenticator_port_initialize']),
        is_dot1x_enabled=dict(type='bool', required=False, default=False),
        cached_reauth_delay=dict(type='int', required=False, default=0),
        allow_gvrp_vlans=dict(type='bool', required=False, default=False),
        use_lldp_data=dict(type='bool', required=False, default=False),
        server_group=dict(type='str', required=False, default=""),
        primary_authentication_method=dict(type='str', required=False,
                                           default='DPAM_LOCAL',
                                           choices=['DPAM_LOCAL',
                                                    'DPAM_EAP_RADIUS',
                                                    'DPAM_CHAP_RADIUS']),
        secondary_authentication_method=dict(type='str', required=False,
                                             default='DSAM_NONE',
                                             choices=['DSAM_NONE',
                                                      'DSAM_AUTHORIZED',
                                                      'DSAM_CACHED_REAUTH']),
        port_id=dict(type='str', required=False, default=""),
        logoff_period=dict(type='int', required=False, default=0),
        is_authenticator_enabled=dict(type='bool', required=False,
                                      default=False),
        control=dict(type='str', required=False, default="DAPC_AUTO",
                     choices=["DAPC_UNAUTHORIZED",
                              "DAPC_AUTO",
                              "DAPC_AUTHORIZED"]),
        unauthorized_vlan_id=dict(type='int', required=False, default=0),
        client_limit=dict(type='int', required=False, default=0),
        quiet_period=dict(type='int', required=False, default=0),
        tx_period=dict(type='int', required=False, default=0),
        supplicant_timeout=dict(type='int', required=False, default=0),
        server_timeout=dict(type='int', required=False, default=0),
        max_requests=dict(type='int', required=False, default=0),
        reauth_period=dict(type='int', required=False, default=0),
        authorized_vlan_id=dict(type='int', required=False, default=0),
        unauth_period=dict(type='int', required=False, default=0),
        cached_reauth_period=dict(type='int', required=False, default=0),
        enforce_cache_reauth=dict(type='bool', required=False, default=False),
        is_port_speed_vsa_enabled=dict(type='bool', required=False,
                                       default=False),
        allow_mbv=dict(type='bool', required=False, default=False),
        controlled_direction=dict(type='str', required=False,
                                  default='DCD_BOTH',
                                  choices=['DCD_BOTH', 'DCD_IN']),
        allow_mixed_users=dict(type='bool', required=False, default=False),
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
        if module.params['command'] == "dot1x_config":
            result = dot1x_config(module)
        elif module.params['command'] == "authenticator_port_config":
            result = authenticator_port_config(module)
        elif module.params['command'] == "authenticator_port_clearstats":
            result = authenticator_port_clearstats(module)
        elif module.params['command'] == "authenticator_port_initialize":
            result = authenticator_port_initialize(module)
        elif module.params['command'] == "authenticator_port_reauthenticate":
            result = authenticator_port_reauthenticate(module)
        elif module.params['command'] == "dot1x_port_security":
            result = dot1x_port_security(module)
        else:
            result = authentication_method_config(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
