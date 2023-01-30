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
module: arubaoss_interface

short_description: Implements Ansible module for port configuration
                   and management.

version_added: "2.6.0"

description:
    - "This implement rest api's which can be used to configure ports"

options:
    interface:
        description:
            - interface id to be configured
        required: true
        type: str
    description:
        description:
            - interface name/description, to remove the description
              of an interface pass in an empty string ''
        required: false
        type: str
    admin_stat:
        description:
            - interface admin status
        required: false
        type: bool
    qos_policy:
        description:
            - Name of QOS policy profile that needs to applied to port
        required: false
        type: str
    acl_id:
        description:
            - Name ACL profile that needs to applied to port
        required: false
        type: str
    acl_direction:
        description:
            - Direction in which ACL will be applied.
        required: false
        choices: ['AD_INBOUND', 'AD_OUTBOUND', 'AD_CRF']
        type: str
    acl_type:
        description:
            - Type ACL will be applied.
        required: false
        choices: ['AT_STANDARD_IPV4', 'AT_EXTENDED_IPV4', 'AT_CONNECTION_RATE_FILTER']
        default: AT_STANDARD_IPV4
        type: str
    qos_direction:
        description:
            - Qos Direction in which ACL will be applied.
        required: false
        choices: ['QPPD_INBOUND', 'QPPD_OUTBOUND']
        default: QPPD_INBOUND
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
     - name: configure port description
       arubaoss_interface:
         interface: 1
         description: "test_interface"

     - name: configure qos on port
       arubaoss_interface:
         interface: 5
         qos_policy: "my_qos"

     - name: delete qos from port
       arubaoss_interface:
         interface: 5
         qos_policy: "my_qos"
         enable: False

     - name: config acl on ports
       arubaoss_interface:
         interface: 2
         acl_id: test
         acl_type: standard
         acl_direction: in

     - name: delete acl ports stats
       arubaoss_interface:
         state: delete
         interface: 2
         acl_id: test
         acl_type: standard
         acl_direction: in

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA


def config_port(module):

    params = module.params
    url = '/ports/' + module.params['interface']

    data = {'id': params['interface']}

    if params.get('description') is not None:
        data['name'] = params['description']

    if params.get('admin_stat') is not None:
        data['is_port_enabled'] = params['admin_stat']

    result = run_commands(module, url, data, 'PUT', check=url)

    return result


def qos(module):

    params = module.params

    url = '/qos/ports-policies'
    qptqos = '~QPT_QOS'

    # check qos policy is present
    qos_check = '/qos/policies/' + params['qos_policy'] + qptqos
    if not get_config(module, qos_check):
        return {'msg': 'Configure QoS policy first. {0} does not exist'
                .format(params['qos_policy']), 'changed': False}

    if params['state'] == 'create':
        policy_id = params['qos_policy'] + qptqos
        port_config = get_config(module, url)
        if port_config:
            check_config = module.from_json(to_text(port_config))
            for ports in check_config['qos_port_policy_element']:
                if ports['port_id'] == params['interface'] and \
                   ports['policy_id'] == policy_id and \
                   ports['direction'] == params['qos_direction']:
                    ret = {'changed': False}
                    ret.update(ports)
                    return ret

        data = {
            'port_id': params['interface'],
            'policy_id': policy_id,
            'direction': params['qos_direction']
        }
        result = run_commands(module, url, data, 'POST')

    else:
        url_delete = url + '/' + params['interface'] + '-' + \
            params['qos_policy'] + qptqos + '-' + params['qos_direction']
        check_url = url + '/' + params['interface'] + '-' + \
            params['qos_policy'] + qptqos + '/stats'
        result = run_commands(module, url_delete, {},
                              'DELETE', check=check_url)
    return result


def acl(module):

    params = module.params

    if params.get('acl_direction') is None:
        return {'msg': 'Missing parameter: acl_direction', 'changed': False}

    # Check if acl is present
    url = "/ports-access-groups"
    acl_type = params['acl_type']
    direction = params['acl_direction']
    data = {'port_id': params['interface'],
            'acl_id': params['acl_id'] + "~" + acl_type,
            'direction': direction}

    check_acl = '/acls/' + params['acl_id'] + "~" + acl_type
    if not get_config(module, check_acl):
        return {'msg': 'Configure ACL first. {0} does not exist'
                .format(params['acl_id']), 'changed': False}

    delete_url = url + '/' + params['interface'] + '-' + \
        params['acl_id'] + "~" + acl_type + '-' + direction

    config_present = False
    current_acl = get_config(module, url)
    if current_acl:
        check_config = module.from_json(to_text(current_acl))

        for ele in check_config['acl_port_policy_element']:
            if ele['uri'] == delete_url:
                config_present = ele

    if params['state'] == 'create':
        if config_present:
            ret = {'changed': False}
            ret.update(ele)
            return ret
        else:
            result = run_commands(module, url, data, method='POST')
    else:
        if config_present:
            result = run_commands(module, delete_url, method='DELETE')
        else:
            return {'changed': False, 'failed': False, 'msg': 'Not present'}

    return result


def run_module():
    module_args = dict(
        interface=dict(type='str', required=True),
        description=dict(type='str', required=False),
        admin_stat=dict(type='bool', required=False),
        qos_policy=dict(type='str', required=False),
        qos_direction=dict(type='str', required=False, default='QPPD_INBOUND',
                           choices=['QPPD_INBOUND', 'QPPD_OUTBOUND']),
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete']),
        acl_id=dict(type='str', required=False),
        acl_type=dict(type='str', required=False, default='AT_STANDARD_IPV4',
                      choices=['AT_STANDARD_IPV4', 'AT_EXTENDED_IPV4',
                               'AT_CONNECTION_RATE_FILTER']),
        acl_direction=dict(type='str', required=False,
                           choices=['AD_INBOUND', 'AD_OUTBOUND', 'AD_CRF']),
    )

    module_args.update(arubaoss_argument_spec)

    result = dict(changed=False, warnings='Not Supported')

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    port_url = '/ports/' + str(module.params['interface'])
    check_port = get_config(module, port_url)
    if not check_port:
        result = {'msg': 'Port {0} not present on device {1}'
                  .format(module.params['interface'], port_url),
                  'changed': False}
    else:
        try:

            if module.params['qos_policy']:
                result = qos(module)
            elif module.params['acl_id']:
                result = acl(module)
            else:
                result = config_port(module)

        except Exception as err:
            return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
