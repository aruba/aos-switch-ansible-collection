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
module: arubaoss_traffic_class

short_description: implements rest api for traffic class configuration

version_added: "2.4.0"

description:
    - "This implements rest apiis whcih can be used to configure trafic class"

options:
    class_name:
        description:
            - Traffic class name
        required: true
        type: str
    class_type:
        description:
            - Traffic class type
        default: QCT_IP_V4
        choices: [ QCT_IP_V4, QCT_IP_V6 ]
        required: false
        type: str
    dscp_value:
        description:
            - dscp value (0 - 64) to be applied
        required: false
        type: int
    entry_type:
        description:
            - Type of action to take.
        choices: [ QTCET_MATCH, QTCET_IGNORE ]
        required: false
        type: str
    protocol_type:
        description:
            - Protocol type for traffic filter.
        required: false
        choices: [ 'PT_GRE','PT_ESP','PT_AH','PT_OSPF','PT_PIM','PT_VRRP',
                 'PT_ICMP','PT_IGMP','PT_IP','PT_SCTP','PT_TCP','PT_UDP' ]
        type: str
    icmp_type:
        description:
            - Applies to icmp type matching this field. Only PT_ICMP
              protocol_type support icmp_code
        required: false
        default: -1
        type: int
    icmp_code:
        description:
            - Applies to icmp code matching this field. Only PT_ICMP
              protocol_type support icmp_code
        required: false
        default: -1
        type: int
    igmp_type:
        description:
            - Applies to igmp type matching this field. Only PT_IGMP
              protocol_type support igmp_type
        required: false
        choices: [ IT_HOST_QUERY, IT_HOST_REPORT, IT_DVMRP, IT_PIM, IT_TRACE,
                  IT_V2_HOST_REPORT, IT_V2_HOST_LEAVE, IT_MTRACE_REPLY,
                  IT_MTRACE_REQUEST, IT_V3_HOST_REPORT, IT_MROUTER_ADVERTISEMENT,
                  IT_MROUTER_SOLICITATION, IT_MROUTER_TERMINATION ]
        type: str
    match_bit:
        description:
            - The set of tcp match bits . Only PT_TCP  protocol_type
              support match_bit
        required: false
        choices: [ MB_ACK, MB_FIN, MB_RST, MB_SYN ]
        elements: str
        type: list
    source_port:
        description:
            - Applies to source port matching this filter. Only PT_SCTP,
              PT_TCP and PT_UDP Protocol types support source_port
        required: false
        type: dict
    destination_port:
        description:
            - Applies to destination port matching this filter. Only
              PT_SCTP,PT_TCP and PT_UDP Protocol types support
              destination_port
        required: false
        type: dict
    source_ip_address:
        description:
            - Applies to source IP Address/Subnet matching this
              extended traffic filter
        required: false
        type: str
    source_ip_mask:
        description:
            - Net mask source_ip_address
        required: false
        type: str
    destination_ip_address:
        description:
            - Applies to destination IP Address/Subnet matching this
              extended traffic filter
        required: false
        type: str
    destination_ip_mask:
        description:
            - Net mask destination_ip_address
        required: false
        type: str
    device_type:
        description:
            - Applies to device type matching this extended traffic filter
        required: false
        type: str
    application_type:
        description:
            - Applies to application matching this extended traffic filter
        required: false
        type: str
    precedence:
        description:
            - IP precedence flag
        required: false
        type: int
    tos:
        description:
            - Tos value
        required: false
        type: int
    sequence_no:
        description:
            - Sequence number for the traffic class configured
        required: false
        default: -1
        type: int
    state:
        description: To create or delete traffic class
        choices: [ create, delete ]
        required: False
        default: create
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
      - name: create traffic class
        arubaoss_traffic_class:
          class_name: my_class

      - name: add match criteria
        arubaoss_traffic_class:
          class_name: my_class
          icmp_code: 1
          icmp_type: 1
          source_ip_address: 0.0.0.0
          source_ip_mask: 255.255.255.255
          destination_ip_address: 0.0.0.0
          destination_ip_mask: 255.255.255.255
          protocol_type: "PT_ICMP"
          entry_type: QTCET_MATCH

      - name: add udp traffic ignore rule
        arubaoss_traffic_class:
          class_name: my_class
          source_ip_address: 0.0.0.0
          source_ip_mask: 255.255.255.255
          destination_ip_address: 0.0.0.0
          destination_ip_mask: 255.255.255.255
          protocol_type: "PT_UDP"
          entry_type: QTCET_IGNORE
          destination_port: {"port_not_equal": 0,
                             "port_range_start": 443,
                             "port_range_end": 443}

      - name: delete traffic class
        arubaoss_traffic_class:
          class_name: my_class
          state: delete

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA


def traffic_class(module):

    params = module.params
    url = '/qos/traffic-classes'
    class_id = params['class_name'] + '~' + params['class_type']

    check_url = url + '/' + class_id

    if params['state'] == 'create':
        data = {
            'class_name': params['class_name'],
            'class_type': params['class_type']
        }
        method = 'POST'

    elif params['state'] == 'delete':

        qos_url = '/qos/policies'
        qos_config = get_config(module, qos_url)

        if qos_config:
            check_config = module.from_json(to_text(qos_config))
            port_url = '/qos/ports-policies'
            port_config = get_config(module, port_url)
            if port_config:
                port_config = module.from_json(to_text(port_config))

            # Check if qos is applied to any vlan
            vlan_url = '/qos/vlans-policies'
            vlan_config = get_config(module, vlan_url)
            if vlan_config:
                vlan_config = module.from_json(to_text(vlan_config))

            for qos in check_config['qos_policy_element']:
                # Check if qos is applied to any port
                class_url = qos_url + '/' + qos['id'] + '/policy-actions'
                class_config = get_config(module, class_url)
                check_class = module.from_json(to_text(class_config))
                if check_class:
                    for qos_action in check_class['qos_policy_action_element']:
                        if qos_action['traffic_class_id'] == class_id:
                            for port in port_config['qos_port_policy_element']:
                                if qos['id'] == port['policy_id']:
                                    return {'msg': 'Class {0} is active in qos '
                                            'policy {1} for port {2}.Remove qos '
                                            'policy first'
                                            .format(class_id, qos['id'],
                                                    port['port_id']),
                                            'changed': False}

                            for vlan in vlan_config['qos_vlan_policy_element']:
                                if qos['id'] == vlan['policy_id']:
                                    return {'msg': 'Class {0} is active in qos '
                                            'policy {1} for vlan {2}.Remove qos '
                                            'policy first'
                                            .format(class_id, qos['id'],
                                                    vlan['vlan_id']),
                                            'changed': False}

        url = check_url
        data = {}
        method = 'DELETE'

    result = run_commands(module, url, data, method, check=check_url)

    return result


def traffic_class_match(module):

    params = module.params

    class_id = params['class_name'] + '~' + params['class_type']

    url = '/qos/traffic-classes/' + class_id

    # Create traffic class if not present
    traffic_class(module)

    if params['class_type'] == 'QCT_IP_V4':
        version = 'IAV_IP_V4'
    else:
        version = 'IAV_IP_V6'

    match_url = url + '/matches'
    if params['sequence_no'] > 0:
        url = match_url + '/' + str(params['sequence_no'])
        method = 'PUT'
    else:
        url = match_url
        method = 'POST'

    if params['state'] == 'create':

        protocol = params.get('protocol_type')
        if not protocol:
            return {'msg': 'protocol_type is required', 'changed': False}

        data = {
            'traffic_class_id': class_id,
            'entry_type': params['entry_type'],
        }

        if params['dscp_value']:
            data['dscp_value'] = params['dscp_value']

        data.update({
            "traffic_match": {
                "protocol_type": params['protocol_type'],
                "source_ip_address": {
                    "version": version,
                    "octets": params['source_ip_address']
                },
                "source_ip_mask": {
                    "version": version,
                    "octets": params['source_ip_mask']
                },
                "destination_ip_address": {
                    "version": version,
                    "octets": params['destination_ip_address']
                },
                "destination_ip_mask": {
                    "version": version,
                    "octets": params['destination_ip_mask']
                }
            }
        })

        if protocol == 'PT_ICMP':
            if params['icmp_type'] > -1:
                data['traffic_match']['icmp_type'] = params['icmp_type']
            if params['icmp_code'] > -1:
                data['traffic_match']['icmp_code'] = params['icmp_code']

        if protocol == 'PT_IGMP':
            if params['igmp_type']:
                data['traffic_match']['igmp_type'] = params['igmp_type']

        if protocol == 'PT_TCP':
            if params['match_bit']:
                data['traffic_match']['match_bit'] = params['match_bit']

        if protocol in ('PT_SCTP', 'PT_TCP', 'PT_UDP'):
            if params['source_port']:
                data['traffic_match']['source_port'] = params['source_port']

            if params['destination_port']:
                data['traffic_match']['destination_port'] = \
                    params['destination_port']

        if params['precedence']:
            data['traffic_match']['precedence'] = params['precedence']

        if params['tos']:
            data['traffic_match']['tos'] = params['tos']

        qos_config = get_config(module, match_url)
        if qos_config:
            check_config = module.from_json(to_text(qos_config))
            for config in check_config['qos_class_match_element']:
                if config['traffic_match']['protocol_type'] == 'PT_TCP':
                    config['traffic_match'].pop('is_connection_established')

                if params['entry_type'] == config['entry_type'] and \
                        config['traffic_match'] == data['traffic_match']:
                    ret = {'changed': False}
                    ret.update(config)
                    return ret

        result = run_commands(module, url, data, method)
        message = result.get('body') or None
        if message:
            if 'Duplicate' in message or 'Configuration Failed' in message:
                result = {'changed': False}
                result['failed'] = False
                result['message'] = message
                result.update(data)
                return result

    else:
        result = run_commands(module, url, {}, 'DELETE', check=url)

    return result


def run_module():
    module_args = dict(
        class_name=dict(type='str', required=True),
        class_type=dict(type='str', required=False, default='QCT_IP_V4',
                        choices=['QCT_IP_V4', 'QCT_IP_V6']),
        dscp_value=dict(type='int', required=False),
        state=dict(type='str', required=False, default='create',
                   choices=['create', 'delete']),
        sequence_no=dict(type='int', required=False, default=-1),
        entry_type=dict(type='str', required=False,
                        choices=['QTCET_MATCH', 'QTCET_IGNORE']),
        protocol_type=dict(type='str', required=False,
                           choices=['PT_GRE', 'PT_ESP', 'PT_AH', 'PT_OSPF',
                                    'PT_PIM', 'PT_VRRP', 'PT_ICMP',
                                    'PT_IGMP', 'PT_IP', 'PT_SCTP',
                                    'PT_TCP', 'PT_UDP']),
        icmp_type=dict(type='int', required=False, default=-1),
        icmp_code=dict(type='int', required=False, default=-1),
        igmp_type=dict(type='str', required=False,
                       choices=['IT_HOST_QUERY', 'IT_HOST_REPORT',
                                'IT_DVMRP', 'IT_PIM', 'IT_TRACE',
                                'IT_V2_HOST_REPORT', 'IT_V2_HOST_LEAVE',
                                'IT_MTRACE_REPLY', 'IT_MTRACE_REQUEST',
                                'IT_V3_HOST_REPORT',
                                'IT_MROUTER_ADVERTISEMENT',
                                'IT_MROUTER_SOLICITATION',
                                'IT_MROUTER_TERMINATION']),
        match_bit=dict(type='list', required=False, elements='str',
                       choices=['MB_ACK', 'MB_FIN', 'MB_RST', 'MB_SYN']),
        source_port=dict(type='dict', required=False),
        destination_port=dict(type='dict', required=False),
        source_ip_address=dict(type='str', required=False),
        source_ip_mask=dict(type='str', required=False),
        destination_ip_address=dict(type='str', required=False),
        destination_ip_mask=dict(type='str', required=False),
        device_type=dict(type='str', required=False,),
        application_type=dict(type='str', required=False),
        precedence=dict(type='int', required=False),
        tos=dict(type='int', required=False),
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

        if module.params['entry_type']:
            result = traffic_class_match(module)
        else:
            result = traffic_class(module)

    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
