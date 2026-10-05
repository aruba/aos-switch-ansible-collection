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

"""arubaoss_loop_protect command=update changes what the task sets, and nothing else.

It sent all four global settings, unset ones from defaults, so setting one
reset the other three. And it sent two under misspelled names -
port_disable_timer_in_senconds and trasmit_interval_in_seconds - where the
switch's own fields are port_disable_timer_in_seconds and
transmit_interval_in_seconds. run_commands() compares only the fields the
switch returns, so a task setting either of those two alone never wrote.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from ansible_collections.arubanetworks.aos_switch.plugins.modules import arubaoss_loop_protect
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)


def a_switch_in_vlan_mode():
    # The fields a 2930F on WC.16.11.0031 returns for GET /rest/v7/loop_protect,
    # with every value changed from its default.
    return FakeSwitch({'/loop_protect': {
        'uri': '/loop_protect',
        'port_disable_timer_in_seconds': 30,
        'transmit_interval_in_seconds': 10,
        'mode': 'LPM_VLAN',
        'is_trap_on_loop_detected_enabled': False,
    }})


def sent(switch):
    return [body for method, path, body in switch.writes if path == '/loop_protect']


class TestLoopProtect(unittest.TestCase):

    def test_turning_on_traps_keeps_the_other_three_settings(self):
        switch = a_switch_in_vlan_mode()
        result = run_module(arubaoss_loop_protect, {'command': 'update', 'trap': True}, switch)
        self.assertFalse(result.get('failed'), result)
        self.assertEqual(sent(switch), [{
            'port_disable_timer_in_seconds': 30,
            'transmit_interval_in_seconds': 10,
            'mode': 'LPM_VLAN',
            'is_trap_on_loop_detected_enabled': True,
        }])

    def test_a_disable_timer_on_its_own_is_written(self):
        switch = a_switch_in_vlan_mode()
        result = run_module(arubaoss_loop_protect,
                            {'command': 'update', 'port_disable_timer': 120}, switch)
        self.assertTrue(result.get('changed'), result)
        self.assertEqual(switch.resources['/loop_protect']['port_disable_timer_in_seconds'], 120)
        self.assertEqual(switch.resources['/loop_protect']['mode'], 'LPM_VLAN')

    def test_without_a_current_config_the_old_defaults_fill_the_gaps(self):
        switch = FakeSwitch()
        run_module(arubaoss_loop_protect, {'command': 'update', 'trap': True}, switch)
        self.assertEqual(sent(switch), [{
            'port_disable_timer_in_seconds': 0,
            'transmit_interval_in_seconds': 5,
            'mode': 'LPM_PORT',
            'is_trap_on_loop_detected_enabled': True,
        }])


if __name__ == '__main__':
    unittest.main()
