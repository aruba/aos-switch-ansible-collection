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

"""The harness itself: a module run against FakeSwitch logs in, writes and logs out."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from ansible_collections.arubanetworks.aos_switch.plugins.modules import arubaoss_user, arubaoss_vlan
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)


class TestHarness(unittest.TestCase):

    def test_a_vlan_is_created_with_one_post(self):
        switch = FakeSwitch()
        result = run_module(arubaoss_vlan, {'vlan_id': 4093, 'name': 'probe'}, switch)
        self.assertTrue(result.get('changed'), result)
        self.assertNotIn('failed', result)
        self.assertEqual([(m, p) for m, p, _ in switch.writes], [('POST', '/vlans')])
        self.assertEqual(switch.writes[0][2]['vlan_id'], 4093)
        # Every login is matched by a logout.
        sessions = [m for m, p, _ in switch.requests if p == '/login-sessions']
        self.assertEqual(sessions.count('POST'), sessions.count('DELETE'))

    def test_warnings_reach_the_result_after_controller_code_is_imported(self):
        # Importing a controller plugin, as test_command_connection_failure
        # does, marks the whole process as a controller, and from then on
        # AnsibleModule.warn() writes to the controller's display instead of
        # the result. A module never runs in the controller's process.
        import ansible.plugins.cliconf  # noqa: F401 pylint: disable=unused-import
        result = run_module(arubaoss_user, {'user_name': 'operator', 'user_password': 'x'},
                            FakeSwitch({'/system/include-credentials': {
                                'include_credentials_in_response': 'ICS_DISABLED'}}))
        messages = [w['event']['msg'] if isinstance(w, dict) else w
                    for w in result.get('warnings', [])]
        self.assertTrue(any('no_log' in m for m in messages), result)


if __name__ == '__main__':
    unittest.main()
