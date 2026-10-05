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

"""A CLI command fails when the SSH connection does, instead of reporting ok.

The collection's cliconf run_commands() catches AnsibleConnectionFailure and,
unless check_rc is set, returns the exception's text as the command's output.
run_cli_commands() did not set it, so for arubaoss_command and
arubaoss_config a connection that never established - an unreachable host,
or no shared key exchange - came back as output, and the task reported ok.
For arubaoss_config that includes `write memory`.

These tests drive the real Cliconf.run_commands() over a stand-in transport,
and turn what it raises into ConnectionError, as the persistent connection's
JSON-RPC does for the module.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest

from unittest import mock

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.connection import ConnectionError

from ansible_collections.arubanetworks.aos_switch.plugins.cliconf.arubaoss import Cliconf
from ansible_collections.arubanetworks.aos_switch.plugins.module_utils import arubaoss
from ansible_collections.arubanetworks.aos_switch.plugins.modules import (
    arubaoss_command, arubaoss_config)
from ansible_collections.arubanetworks.aos_switch.tests.unit.plugins.modules.aoss_harness import (
    FakeSwitch, run_module)

KEX = 'Incompatible ssh peer (no acceptable kex algorithm)'


class Transport(object):
    """The network_cli side: answers each command, or raises as a dead link does."""

    def __init__(self, answer=None, failure=None):
        self.answer = answer
        self.failure = failure

    def send(self, **kwargs):
        if self.failure:
            raise AnsibleConnectionFailure(self.failure)
        return self.answer

    def queue_message(self, *args, **kwargs):
        pass


def connection_over(transport):
    class RpcConnection(object):
        def __init__(self, socket_path):
            self._cliconf = Cliconf(transport)

        def run_commands(self, commands=None, check_rc=False):
            try:
                return self._cliconf.run_commands(commands=commands, check_rc=check_rc)
            except Exception as exc:
                raise ConnectionError(to_text(exc))
    return RpcConnection


def run_command_over(transport):
    with mock.patch.object(arubaoss, 'Connection', connection_over(transport)):
        return run_module(arubaoss_command, {'commands': ['show flash']}, FakeSwitch())


def write_memory_over(transport):
    with mock.patch.object(arubaoss, 'Connection', connection_over(transport)):
        return run_module(arubaoss_config, {'save_when': 'always'}, FakeSwitch())


class TestCommandConnectionFailure(unittest.TestCase):

    def test_a_connection_that_never_established_fails_the_task(self):
        result = run_command_over(Transport(failure=KEX))
        self.assertTrue(result.get('failed'), result)
        self.assertIn(KEX, result.get('msg', ''))
        self.assertNotIn('stdout', result)

    def test_a_write_memory_that_never_ran_fails_the_task(self):
        result = write_memory_over(Transport(failure=KEX))
        self.assertTrue(result.get('failed'), result)
        self.assertIn(KEX, result.get('msg', ''))

    def test_a_command_that_runs_still_returns_its_output(self):
        result = run_command_over(Transport(answer=b'Image Size (bytes) Date Version'))
        self.assertFalse(result.get('failed'), result)
        self.assertEqual(result['stdout'], ['Image Size (bytes) Date Version'])


if __name__ == '__main__':
    unittest.main()
