# Copyright (c) 2026 James Stanton
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

"""arubaoss_system_attributes sends device_operation_mode only when the task sets it.

It defaulted to DOM_AUTONOMOUS and was sent on every call, so a task that
set only the hostname of a switch in DOM_CLOUD also moved it to
DOM_AUTONOMOUS.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from ansible_collections.arubanetworks.aos_switch.plugins.modules import arubaoss_system_attributes
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)


def a_cloud_mode_switch():
    # The fields a 2930F on WC.16.11.0031 returns for GET /rest/v7/system,
    # with the values changed.
    return FakeSwitch({'/system': {
        'name': 'old-name',
        'location': '',
        'contact': '',
        'device_operation_mode': 'DOM_CLOUD',
        'default_gateway': {'version': 'IAV_IP_V4', 'octets': '192.0.2.1'},
        'rollback_to_good_config': None,
    }})


def sent_to_system(switch):
    return [body for method, path, body in switch.writes if path == '/system']


class TestSystemAttributes(unittest.TestCase):

    def test_a_rename_leaves_the_operation_mode_alone(self):
        switch = a_cloud_mode_switch()
        result = run_module(arubaoss_system_attributes, {'hostname': 'new-name'}, switch)
        self.assertFalse(result.get('failed'), result)
        self.assertEqual(sent_to_system(switch), [{'name': 'new-name'}])
        self.assertEqual(switch.resources['/system']['device_operation_mode'], 'DOM_CLOUD')

    def test_an_operation_mode_the_task_sets_is_sent(self):
        switch = a_cloud_mode_switch()
        run_module(arubaoss_system_attributes,
                   {'device_operation_mode': 'DOM_AUTONOMOUS'}, switch)
        self.assertEqual(sent_to_system(switch), [{'device_operation_mode': 'DOM_AUTONOMOUS'}])


if __name__ == '__main__':
    unittest.main()
