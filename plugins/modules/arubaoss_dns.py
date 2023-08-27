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
module: arubaoss_dns

short_description: implements rest api for DNS configuration

version_added: "2.4.0"

description:
    - "This implements rest apis which can be used to configure DNS"

options:
    dns_config_mode:
        description: DNS Configuration Mode, default is DCM_DHCP
        choices: [DCM_DHCP, DCM_MANUAL, DCM_DISABLED]
        required: False
        type: str
        default: 'DCM_MANUAL'
    dns_domain_names:
        description: The first  manually configured DNS server domain name,
          all DNS configurations need to be made in a single module call,
          to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    dns_domain_names_2:
        description: The second  manually configured DNS server domain name,
          all DNS configurations need to be made in a single module call,
          to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    dns_domain_names_3:
        description: The third  manually configured DNS server domain name,
          all DNS configurations need to be made in a single module call,
          to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    dns_domain_names_4:
        description: The fourth  manually configured DNS server domain name,
          all DNS configurations need to be made in a single module call,
          to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    dns_domain_names_5:
        description: The fifth  manually configured DNS server domain name,
          all DNS configurations need to be made in a single module call,
          to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    server_1:
        description: The first manually configured DNS Server IP address
          with priority 1, all DNS configurations need to be made in a
          single module call, to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    version_1:
        description: The ip version of first manually configured DNS Server.
          (V6 is not supported via REST)
        choices: [IAV_IP_V4]
        type: str
        required: False
        default: 'IAV_IP_V4'
    server_2:
        description: The second manually configured DNS Server IP address
          with priority 2, all DNS configurations need to be made in a
          single module call
        type: str
        default: ''
        required: False
    version_2:
        description: The ip version of second manually configured DNS Server.
          (V6 is not supported via REST)
        choices: [IAV_IP_V4]
        type: str
        required: False
        default: 'IAV_IP_V4'
    server_3:
        description: The third manually configured DNS Server IP address
          with priority 3, all DNS configurations need to be made in a
          single module call, to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    version_3:
        description: The ip version of third manually configured DNS Server.
          (V6 is not supported via REST)
        choices: [IAV_IP_V4]
        type: str
        required: False
        default: 'IAV_IP_V4'
    server_4:
        description: The fourth manually configured DNS Server IP address
          with priority 4, all DNS configurations need to be made in a single
          module call, to remove configuration pass in empty string ""
        type: str
        default: ''
        required: False
    version_4:
        description: The ip version of fourth manually configured DNS Server.
          (V6 is not supported via REST)
        choices: [IAV_IP_V4]
        type: str
        required: False
        default: 'IAV_IP_V4'

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
    - name: Configure Maximum DNS Domains and DNS Server
      arubaoss_dns:
        dns_domain_names: "mydomain.com"
        dns_domain_names_2: "myotherdomain.com"
        dns_domain_names_3: myotherotherdomain.com
        dns_domain_names_4: yourdomain.com
        dns_domain_names_5: otherdomain.com
        server_1: "10.2.3.4"
        server_2: "10.2.3.5"
        server_3: "10.2.3.6"
        server_4: "10.2.3.7"

    - name: Configure Remove all DNS Domains and DNS Server 3 and 4
      arubaoss_dns:
        server_1: "10.2.3.4"
        server_2: "10.2.3.5"
        server_3: ""
        server_4: ""

    - name: Configure DNS to be DHCP
      arubaoss_dns:
        dns_config_mode: "DCM_DHCP"

    - name: Disable DNS
      arubaoss_dns:
        dns_config_mode: "DCM_DISABLED"

    - name: Configure DNS Server with priority 4
      arubaoss_dns:
        dns_config_mode: "DCM_MANUAL"
        server_4: "10.2.3.4"

    - name: Configure DNS Server with priority 4 and priority 1
      arubaoss_dns:
        dns_config_mode: "DCM_MANUAL"
        server_1: "10.2.3.1"
        server_4: "10.2.3.4"
'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA


"""
-------
Name: config

Configures port with system_attributes config

param request: module

Returns
 Configure the switch with params sent
-------
"""


def config(module):

    params = module.params
    dnsList = []
    dnsServerList = []
    idval = 1
    data = {'dns_config_mode': params['dns_config_mode']}

    # Configure the domain names
    for dns in [params['dns_domain_names'], params['dns_domain_names_2'],
                params['dns_domain_names_3'], params['dns_domain_names_4'],
                params['dns_domain_names_5']]:
        if not dns == "" and dns not in dnsList:
            dnsList.append(dns)
    data['dns_domain_names'] = dnsList

    # Configure the dns servers
    for dnsServer in [params['server_1'], params['server_2'],
                      params['server_3'], params['server_4']]:
        if not dnsServer == "" and dnsServer not in dnsServerList:
            dnsServerList.append(dnsServer)
            server = 'server_' + str(idval)
            version = 'version_' + str(idval)

            # Only IPv4 address supported
            if not params[version] == "IAV_IP_V4":
                return {'msg': 'Only IPv4 address mode is supported',
                        'changed': False, 'failed': False}

            data[server] = {'version': params[version],
                            'octets': params[server]}
        idval = idval + 1

    url = '/dns'
    method = 'PUT'

    result = run_commands(module, url, data, method, check=url)
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
        dns_config_mode=dict(type='str', required=False, default="DCM_MANUAL",
                             choices=["DCM_DHCP",
                                      "DCM_MANUAL",
                                      "DCM_DISABLED"]),
        dns_domain_names=dict(type='str', required=False, default=""),
        dns_domain_names_2=dict(type='str', required=False, default=""),
        dns_domain_names_3=dict(type='str', required=False, default=""),
        dns_domain_names_4=dict(type='str', required=False, default=""),
        dns_domain_names_5=dict(type='str', required=False, default=""),
        server_1=dict(type='str', required=False, default=""),
        version_1=dict(type='str', required=False, default="IAV_IP_V4",
                       choices=["IAV_IP_V4"]),
        server_2=dict(type='str', required=False, default=""),
        version_2=dict(type='str', required=False, default="IAV_IP_V4",
                       choices=["IAV_IP_V4"]),
        server_3=dict(type='str', required=False, default=""),
        version_3=dict(type='str', required=False, default="IAV_IP_V4",
                       choices=["IAV_IP_V4"]),
        server_4=dict(type='str', required=False, default=""),
        version_4=dict(type='str', required=False, default="IAV_IP_V4",
                       choices=["IAV_IP_V4"]),
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
        result = config(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
