#!/usr/bin/python
# -*- coding: utf-8 -*-

# (C) Copyright 2020 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: arubaoss_command
version_added: "2.9.0"
short_description: Logs in and executes CLI commands on AOS-Switch device via SSH connection
description:
  - This module allows execution of CLI commands on AOS-Switch devices via SSH connection
author: Aruba Networks (@ArubaNetworks)
options:
  commands:
    description: List of commands to be executed in sequence on the switch. Every command
      will attempt to be executed regardless of the success or failure of the previous
      command in the list. To execute commands in the 'configure' context, you must include
      the 'configure terminal' command or one of its variations before the configuration commands.
      'Show' commands are valid and their output will be printed to the screen, returned by the
      module, and optionally saved to a file. The default module timeout is 30 seconds. To change the
      command timeout, set the variable 'ansible_command_timeout' to the desired time in seconds.
    required: True
    type: list
    elements: str
  wait_for:
    description: A list of conditions to wait to be satisfied before continuing execution.
      Each condition must include a test of the 'result' variable, which contains the output
      results of each already-executed command in the 'commands' list. 'result' is a list
      such that result[0] contains the output from commands[0], results[1] contains the output
      from commands[1], and so on.
    required: False
    aliases: [ 'waitfor' ]
    type: list
    elements: str
  match:
    description: Specifies whether all conditions in 'wait_for' must be satisfied or if just
      any one condition can be satisfied. To be used with 'wait_for'.
    default: 'all'
    choices: ['any', 'all']
    required: False
    type: str
  retries:
    description: Maximum number of retries to check for the expected prompt.
    default: 10
    required: False
    type: int
  interval:
    description: Interval between retries, in seconds.
    default: 1
    required: False
    type: int
  output_file:
    description: Full path of the local system file to which commands' results will be output.
       The directory must exist, but if the file doesn't exist, it will be created.
    required: False
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
'''  # NOQA

EXAMPLES = '''
- name: Execute show commands and configure commands, and output results to file
  arubaoss_command:
    commands: ['show run',
      'show interface 24',
      'config',
      'vlan 2',
        'ip address 10.10.10.10/24',
      'end']
    output_file: /users/Home/configure.cfg
- name: Show running-config and show version, and pass only if all (both) results match
  arubaoss_command:
    commands:
      - 'show run'
      - 'show version'
    wait_for:
      - result[0] contains "vlan 2"
      - result[1] contains "WC.16.09.0010G"
    match: all
    retries: 5
    interval: 5
- name: Show running-config, show version commands output to a file
  arubaoss_command:
    commands: ['show run', 'show version']
    output_file: /users/Home/config_list.cfg
- name: Run ping command with increased command timeout
  vars:
    - ansible_command_timeout: 60
  arubaoss_command:
    commands:
      - ping 10.100.0.12 repetitions 100
    output_file: /users/Home/ping.cfg
'''  # NOQA

RETURN = r''' # '''

import time  # NOQA
from ansible.module_utils._text import to_text  # NOQA
from ansible.module_utils.basic import AnsibleModule  # NOQA
try:
    from ansible.module_utils.network.common.parsing import Conditional  # NOQA
except ImportError:
    from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.parsing import Conditional  # NOQA
try:
    from ansible.module_utils.network.common.utils import to_lines, ComplexList  # NOQA
except ImportError:
    from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_lines, ComplexList  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_cli_commands as run_commands  # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec  # NOQA


def transform_commands(module):
    '''
    Transform the command to a complex list
    '''
    transform = ComplexList(dict(
        command=dict(key=True),
        prompt=dict(type='list'),
        answer=dict(type='list'),
        newline=dict(type='bool', default=True),
        sendonly=dict(type='bool', default=False),
        check_all=dict(type='bool', default=False),
    ), module)

    return transform(module.params['commands'])


def parse_commands(module, warnings):
    '''
    Parse the command
    '''
    commands = transform_commands(module)

    return commands


def main():
    '''
    Main entry point to the module
    '''

    argument_spec = dict(
        commands=dict(type='list', elements="str", required=True),
        wait_for=dict(type='list', elements="str", aliases=['waitfor']),
        match=dict(default='all', choices=['all', 'any']),
        retries=dict(default=10, type='int'),
        interval=dict(default=1, type='int'),
        output_file=dict(type='str', default=None),
    )

    argument_spec.update(arubaoss_argument_spec)

    warnings = list()

    result = {'changed': False, 'warnings': warnings}
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    commands = parse_commands(module, warnings)
    wait_for = module.params['wait_for'] or list()

    try:
        conditionals = [Conditional(c) for c in wait_for]
    except AttributeError as exc:
        module.fail_json(msg=to_text(exc))

    retries = module.params['retries']
    interval = module.params['interval']
    match = module.params['match']

    while retries >= 0:
        responses = run_commands(module, commands)

        for item in list(conditionals):
            if item(responses):
                if match == 'any':
                    conditionals = list()
                    break
                conditionals.remove(item)

        if not conditionals:
            break

        time.sleep(interval)
        retries -= 1

    if conditionals:
        failed_conditions = [item.raw for item in conditionals]
        msg = 'One or more conditional statements have not been satisfied'
        module.fail_json(msg=msg, failed_conditions=failed_conditions)

    commands_list = []
    for command in commands:
        commands_list.append(command['command'])

    if module.params['output_file'] is not None:
        output_file = str(module.params['output_file'])
        with open(output_file, 'w') as output:
            for i, command in enumerate(commands_list):
                output.write("command: ")
                output.write(command)
                output.write("\n")
                output.write("response: ")
                output.write(str(responses[i]))
                output.write("\n")
                output.write("------------------------------------------")
                output.write("\n")

    result.update({
        'stdout': responses,
        'stdout_lines': list(to_lines(responses))
    })
    module.exit_json(**result)


if __name__ == '__main__':
    main()
