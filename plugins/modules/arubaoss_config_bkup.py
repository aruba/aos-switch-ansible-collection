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
module: arubaoss_config_bkup

short_description: Implements Ansible module for switch configuration
                   backup and restore.

version_added: "2.6.0"

description:
    - "This implement rest api's which can be used to backup switch
       configuration from server. Module takes 5 secs to execute each
       task. Default module action is to restore the configuration.
       Use config_type for configuration backup"

options:
    file_name:
        description:
            - configuration file name
        required: true
        type: str
    config_type:
        description:
            - Type of configuration file. If this option is used, configuration
              file is saved to the system.
        choices: [CT_RUNNING_CONFIG, CT_STARTUP_CONFIG]
        required: false
        type: str
    server_type:
        description:
            - server type from/to which configuration needs to be copied
        choices: [ST_FLASH, ST_TFTP, ST_SFTP]
        required: false
        type: str
    forced_reboot:
        description:
            - Apply the configuration with reboot if the configuration
              has reboot required commands
        required: false
        type: bool
    recovery_mode:
        description:
            - To enable or disable recovery mode. Not applicable if
              is_forced_reboot_enabled is true
        required: false
        type: bool
    server_name:
        description:
            - Server name in which file is stored. Not applicable for ST_FLASH.
        required: false
        type: str
    server_ip:
        description:
            - Server ip address in which file is stored. Not applicable for
              ST_FLASH
        required: false
        type: str
    sftp_port:
        description:
            - TCP port number. Applicable for ST_SFTP.
        default: 22
        required: false
        type: int
    wait_for_apply:
        description:
            - Wait if there is already an ongoing configuration change
              on device.
        default: True
        required: false
        type: bool
    state:
        description:
            - Adding or reading data
        default: create
        required: false
        type: str
    user_name:
        description: SFTP server Username
        required: false
        type: str
    server_passwd:
        description: SFTP server password
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
      - name: backup configuration files
        arubaoss_config_bkup:
          file_name: test1
          server_type: ST_TFTP
          server_ip: 192.168.1.2

      - name: backup configuration files
        arubaoss_config_bkup:
          file_name: test1
          config_type: CT_RUNNING_CONFIG

'''

from ansible.module_utils.basic import AnsibleModule  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands, get_config  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA
from ansible.module_utils._text import to_text  # NOQA
from time import sleep  # NOQA


def config_backup(module):

    params = module.params
    url = '/system/config/cfg_backup_files'

    data = {
        'file_name': params['file_name'],
        'config_type': params['config_type']
    }

    if params['state'] == 'create':
        check_config = get_config(module, url)
        if check_config:
            check_config = module.from_json(to_text(check_config))
            if check_config['collection_result']['total_elements_count'] == 5:
                present = False
                for config in check_config['config_file_element']:
                    if config['file_name'] == params['file_name']:
                        present = True
                if not present:
                    return {'msg': 'Only five config files are allowed.',
                            'changed': False}

        result = run_commands(module, url, data, 'POST')

    return result


def config_restore(module):
    params = module.params
    url = '/system/config/cfg_restore'
    url_status = url + '/status'

    server_type = params['server_type']
    data = {
        'file_name': params['file_name'],
        'server_type': server_type,
    }

    if server_type == 'ST_TFTP' or server_type == 'ST_SFTP':
        if not params['server_name'] and not params['server_ip']:
            return {'msg': 'server_name or server_ip is required',
                    'changed': False}

    if server_type == 'ST_TFTP':
        if params['server_name']:
            data.update({
                'tftp_server_address': {
                    'server_address': {
                        'host_name': params['server_name']
                    }
                }
            })
        if params['server_ip']:
            data.update({
                'tftp_server_address': {
                    'server_address': {
                        'ip_address': {
                            'octets': params['server_ip'],
                            'version': 'IAV_IP_V4'
                        }
                    }
                }
            })

    if server_type == 'ST_SFTP':
        if params['server_name']:
            data.update({
                'sftp_server_address': {
                    'server_address': {
                        'host_name': params['server_name']
                    }
                }
            })
        if params['server_ip']:
            data.update({
                'sftp_server_address': {
                    'server_address': {
                        'ip_address': {
                            'octets': params['server_ip'],
                            'version': 'IAV_IP_V4'
                        }
                    }
                }
            })

        data['sftp_server_address']['user_name'] = params['user_name']
        data['sftp_server_address']['password'] = params['server_passwd']
        port = params['sftp_port']
        if port < 1 or port > 65535:
            return {'msg': 'sftp_port range should be between 1-65535',
                    'changed': False}

        data['sftp_server_address']['port_number'] = params['sftp_port']

    # Wait 40 secs for configuration to be applied
    for r in range(20):
        get_status = get_config(module, url_status)
        if get_status:
            get_status = module.from_json(to_text(get_status))
            status = get_status['status']
            if status in ['CRS_IN_PROGRESS', 'CRS_FINDING_FAILED_CMDS',
                          'CRS_CALCULATING_DIFF']:
                if params['wait_for_apply']:
                    sleep(2)
                    module.log(status['status'])
                    continue
                else:
                    return {'msg': 'Config restore is already running: {0}'
                            .format(status), 'changed': False}
        break

    result = run_commands(module, url, data, 'POST', wait_after_send=5)
    message = result.get('body') or None
    if message and 'Configuration changes are temporarily disabled' in message:
        ret = {'message': message}
        ret['changed'] = False
        return ret

    return result


def run_module():
    module_args = dict(
        file_name=dict(type='str', required=True),
        config_type=dict(type='str', required=False,
                         choices=['CT_RUNNING_CONFIG', 'CT_STARTUP_CONFIG']),
        server_type=dict(type='str', required=False,
                         choices=['ST_FLASH', 'ST_TFTP', 'ST_SFTP']),
        forced_reboot=dict(type='bool', required=False),
        recovery_mode=dict(type='bool', required=False),
        server_name=dict(type='str', required=False),
        server_ip=dict(type='str', required=False),
        sftp_port=dict(type='int', required=False, default=22),
        state=dict(type='str', required=False, default='create'),
        wait_for_apply=dict(type='bool', required=False, default=True),
        user_name=dict(type='str', required=False),
        server_passwd=dict(type='str', required=False, no_log=True),
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
        if module.params['config_type']:
            result = config_backup(module)
        else:
            result = config_restore(module)

    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
