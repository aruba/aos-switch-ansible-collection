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

"""A module that cannot predict its change in check mode must not claim to.

Declaring supports_check_mode=True and then exiting with changed=False
before contacting the switch makes --check report "ok" whatever the switch
holds. A module that does not declare it is skipped by Ansible, visibly.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import importlib
import os
import re
import unittest

from ansible_collections.arubanetworks.aos_switch.plugins.modules import (
    arubaoss_captive_portal, arubaoss_vlan)
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)

MODULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', '..', '..', '..', 'plugins', 'modules')

# `if module.check_mode:` followed directly by an exit that reports nothing.
EARLY_EXIT = re.compile(
    r'^\s*if module\.check_mode:\s*\n\s*(module\.exit_json\(\*\*result\)|return result)\s*$',
    re.MULTILINE)


class TestCheckMode(unittest.TestCase):

    def test_a_vlan_the_switch_lacks_is_skipped_not_reported_unchanged(self):
        switch = FakeSwitch()
        result = run_module(arubaoss_vlan, {'vlan_id': 4093}, switch, check_mode=True)
        self.assertTrue(result.get('skipped'), result)
        self.assertNotIn('/vlans/4093', switch.resources)
        self.assertEqual(switch.writes, [])

    def test_captive_portal_whose_exit_had_an_else_branch_is_skipped(self):
        switch = FakeSwitch()
        result = run_module(arubaoss_captive_portal, {}, switch, check_mode=True)
        self.assertTrue(result.get('skipped'), result)
        self.assertEqual(switch.writes, [])

    def test_every_module_imports(self):
        for name in sorted(os.listdir(MODULES)):
            if name.endswith('.py') and name != '__init__.py':
                importlib.import_module(
                    'ansible_collections.arubanetworks.aos_switch.plugins.modules.' + name[:-3])

    def test_no_module_declares_check_mode_and_exits_before_checking(self):
        offenders = []
        for name in sorted(os.listdir(MODULES)):
            if not name.endswith('.py'):
                continue
            with open(os.path.join(MODULES, name)) as f:
                source = f.read()
            if 'supports_check_mode=True' in source and EARLY_EXIT.search(source):
                offenders.append(name[:-3])
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
