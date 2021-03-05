#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (C) Copyright 2021 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config # NOQA
import json # NOQA

class InterfacesFacts(object):
    '''
    Class for PVOS Interface facts
    '''

    def __init__(self, module, subspec='config', options='options'):
        '''
        init function
        '''
        self._module = module

    def populate_facts(self, connection, ansible_facts, data=None):
        '''
        Obtain and return interfaces facts
        '''
        url = '/ports'
        check_presence = get_config(self._module, url)
        if check_presence:
           ports = json.loads(check_presence)

        facts = {
            'interfaces': ports
        }
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts
