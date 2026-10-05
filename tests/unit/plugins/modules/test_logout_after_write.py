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

"""A logout that fails after a write must not hide the write.

Writing the manager user ends the switch's REST session, so the DELETE on
/login-sessions that follows is refused with HTTP 400, "The REST session
timed out. Please login." The password has changed by then. Reporting the
task as failed tells the user the opposite of what happened.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from ansible_collections.arubanetworks.aos_switch.plugins.modules import arubaoss_user
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)

USER = '/management-user/UT_MANAGER'
ARGS = {
    'user_name': 'manager',
    'user_type': 'UT_MANAGER',
    'user_password': 'the-new-password',
    'password_type': 'PET_PLAIN_TEXT',
    'state': 'create',
}


def a_switch_whose_session_ends_when_the_user_is_written():
    switch = FakeSwitch({
        USER: {'type': 'UT_MANAGER', 'name': 'manager', 'password_type': 'PET_PLAIN_TEXT'},
        '/system/include-credentials': {'include_credentials_in_response': 'ICS_DISABLED'},
    })

    def end_the_session(switch, method, path, body):
        if path == USER:
            switch.logout_status = 400

    switch.on_write = end_the_session
    return switch


class TestLogoutAfterWrite(unittest.TestCase):

    def test_a_write_that_ends_the_session_is_reported_changed_not_failed(self):
        switch = a_switch_whose_session_ends_when_the_user_is_written()
        result = run_module(arubaoss_user, ARGS, switch)
        self.assertIn(('PUT', USER), [(m, p) for m, p, _ in switch.writes])
        self.assertFalse(result.get('failed'), result)
        self.assertTrue(result.get('changed'), result)
        warnings = [w['event']['msg'] if isinstance(w, dict) else w
                    for w in result.get('warnings', [])]
        self.assertTrue(any('HTTP 400' in w and 'logout' in w.lower() for w in warnings),
                        warnings)

    def test_a_logout_that_fails_before_any_write_still_fails(self):
        # Reading the existing user is followed by a logout too. Nothing has
        # been written yet, so that failure is still reported as one.
        switch = a_switch_whose_session_ends_when_the_user_is_written()
        switch.logout_status = 400
        result = run_module(arubaoss_user, ARGS, switch)
        self.assertTrue(result.get('failed'), result)
        self.assertEqual(switch.writes, [])


if __name__ == '__main__':
    unittest.main()
