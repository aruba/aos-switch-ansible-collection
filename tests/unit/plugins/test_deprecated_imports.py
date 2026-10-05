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

"""No plugin imports ansible.module_utils._text, which ansible-core removes in 2.24.

ansible-core 2.21 already warns on every such import: "Importing 'to_text'
from 'ansible.module_utils._text' is deprecated", removal version 2.24. Its
replacement, ansible.module_utils.common.text.converters, exists from
ansible-core 2.10, this collection's minimum.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import unittest

PLUGINS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'plugins')


class TestDeprecatedImports(unittest.TestCase):

    def test_no_plugin_imports_module_utils_text(self):
        offenders = []
        for root, dirs, files in os.walk(PLUGINS):
            for name in files:
                if name.endswith('.py'):
                    path = os.path.join(root, name)
                    with open(path) as f:
                        if 'ansible.module_utils._text' in f.read():
                            offenders.append(os.path.relpath(path, PLUGINS))
        self.assertEqual(sorted(offenders), [])


if __name__ == '__main__':
    unittest.main()
