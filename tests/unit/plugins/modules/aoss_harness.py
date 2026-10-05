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

"""A stand-in AOS-Switch REST API, and a runner for modules against it.

FakeSwitch answers the calls Aossapi makes through fetch_url: login and
logout on /login-sessions, GET /version, and GET, POST, PUT and DELETE on
resources held in a dict. It records every request, so a test can assert on
exactly what a module sent - including that it sent nothing.

run_module() runs a module's main() against a FakeSwitch and returns the
result the module printed.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import contextlib
import io
import json
import re

from unittest import mock

from ansible.module_utils import basic

from ansible_collections.arubanetworks.aos_switch.plugins.module_utils import arubaoss

PROVIDER = {
    'host': 'switch.example',
    'username': 'manager',
    'password': 'not-a-real-password',
    'use_ssl': False,
}

# Aossapi's URLs are /rest/<version>/<path>, except GET /rest/version.
_URL = re.compile(r'^https?://[^/]+/rest(?:/v[0-9.]+)?(?P<path>/.*)$')


class Response(object):
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body


class FakeSwitch(object):

    def __init__(self, resources=None, firmware='WC.16.10.0012'):
        # Several modules read the firmware version before they write.
        self.resources = {'/system/status': {'firmware_version': firmware}}
        self.resources.update(resources or {})
        # (method, path, body), for every request, in order.
        self.requests = []
        # What DELETE /login-sessions answers. A test can change it, from
        # on_write for instance, to model the switch ending a session.
        self.logout_status = 204
        # Called as on_write(switch, method, path, body) after each write.
        self.on_write = None

    @property
    def writes(self):
        """The requests that change configuration: not logins or reads."""
        return [r for r in self.requests
                if r[0] in ('POST', 'PUT', 'DELETE') and r[1] != '/login-sessions']

    def fetch_url(self, module, url, data=None, headers=None, method=None, **kwargs):
        method = (method or 'GET').upper()
        path = _URL.match(url).group('path')
        body = json.loads(data) if data else None
        self.requests.append((method, path, body))
        info = {'url': url, 'msg': 'OK'}

        if path == '/login-sessions':
            if method == 'POST':
                info.update({'status': 201, 'set-cookie': 'sessionId=fake'})
                return Response(b'{}'), info
            info['status'] = self.logout_status
            if self.logout_status != 204:
                info['msg'] = 'HTTP Error %d' % self.logout_status
                info['body'] = '{"message": "The REST session timed out. Please login."}'
            return None, info

        if path == '/version':
            info['status'] = 200
            return Response(json.dumps(
                {'version_element': [{'version': 'v7.0'}]}).encode()), info

        if method == 'GET':
            if path in self.resources:
                info['status'] = 200
                return Response(json.dumps(self.resources[path]).encode()), info
            info.update({'status': 404, 'msg': 'HTTP Error 404'})
            return None, info

        if method == 'DELETE':
            self.resources.pop(path, None)
            info['status'] = 204
        else:
            current = dict(self.resources.get(path) or {})
            current.update(body or {})
            self.resources[path] = current
            info['status'] = 200
        if self.on_write:
            self.on_write(self, method, path, body)
        if info['status'] == 204:
            return None, info
        return Response(json.dumps(self.resources[path]).encode()), info


@contextlib.contextmanager
def _module_args(args):
    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:
        # ansible-core before 2.19
        from ansible.module_utils.common.text.converters import to_bytes
        with mock.patch.object(basic, '_ANSIBLE_ARGS',
                               to_bytes(json.dumps({'ANSIBLE_MODULE_ARGS': args}))):
            yield
        return
    with patch_module_args(args):
        yield


def run_module(module, args, switch, check_mode=False):
    """Run module.main() against switch, and return the result it printed."""
    args = dict(args)
    args.setdefault('provider', PROVIDER)
    if check_mode:
        args['_ansible_check_mode'] = True
    out = io.StringIO()
    # Aossapi caches its connection in a module global.
    arubaoss._DEVICE_CONNECTION = None
    try:
        with _module_args(args), \
                mock.patch.object(arubaoss, 'fetch_url', switch.fetch_url), \
                mock.patch.object(arubaoss, 'sleep', lambda seconds: None), \
                contextlib.redirect_stdout(out):
            try:
                module.main()
            except SystemExit:
                pass
    finally:
        arubaoss._DEVICE_CONNECTION = None
    lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
    return json.loads(lines[-1])
