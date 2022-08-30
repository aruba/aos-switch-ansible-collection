#!/usr/bin/python
#
# Copyright (c) 2020 Hewlett Packard Enterprise Development LP
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
module: arubaoss_anycli

short_description: implements rest api to execute CLI command via anyCLI uri

version_added: "2.10"

description:
    - "This implements rest apis which can be used to support anyCLI"

options:
    command:
        description: command to be executed
        required: true
        type: str

author:
    - Stella Rajan (@hpe)
'''

EXAMPLES = '''
     - name: create vlan using cliCommand
       arubaoss_anycli:
         command: "vlan 100"

      - name: View the running config in the system
        arubaoss_anycli:
          command: "show running-config

      - name: configure ip mtu
        arubaoss_anycli:
          command: "jumbo ip-mtu 1600"
'''

from ansible.module_utils.basic import AnsibleModule # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import run_commands # NOQA
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import arubaoss_argument_spec # NOQA

"""
-------
Name: cli_command

Executes the cli command

param request: module

Returns
 Configure the switch with params sent
-------
"""


def cli_command(module):

    params = module.params
    data = {}

    if not params['command'] == "":
        data['cmd'] = params['command']

    url = '/cli'
    method = 'POST'

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
        command=dict(type='str', required=False, default=''),
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
        result = cli_command(module)
    except Exception as err:
        return module.fail_json(msg=err)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
