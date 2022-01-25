#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (C) Copyright 2021 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.arubanetworks.aos_switch.plugins.module_utils.arubaoss import get_config # NOQA
import json # NOQA

class FactsBase(object):
    '''
    FactsBase class
    '''

    def __init__(self, module):
        self._module = module
        self.warnings = list()
        self.facts = dict()
        self.responses = None
        self._url = None
        self._fact_name = None
        self.data = None

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        if self._fact_name == 'host_system_info':
          try:
             check_presence = get_config(self._module, self._url)
             self.data = json.loads(check_presence)
          except Exception:
             stacked_check_presence = get_config(self._module, self._stacked_url)
             self.data = json.loads(stacked_check_presence)
        else:
          check_presence = get_config(self._module, self._url)
          if check_presence:
            self.data = json.loads(check_presence)

        if self._fact_name == 'switch_specific_system_info':
            self.facts['switch_specific_system_info'] = self.data
            return

        if self._fact_name == 'host_system_info':
            self.facts['host_system_info'] = self.data
            return

        if type(self.data) == dict and self._fact_name in self.data.keys():
            self.facts[self._fact_name] = self.data[self._fact_name]


class HostSystemInfo(FactsBase):
    '''
    Host System Info facts class
    '''

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        self._fact_name = 'host_system_info'
        self._url = '/system/status'
        self._stacked_url = '/system/status/global_info'
        super(HostSystemInfo, self).populate()


class SwitchSpecificSystemInfo(FactsBase):
    '''
    Switch Specific System Info facts class
    '''

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        self._fact_name = 'switch_specific_system_info'
        self._url = '/system/status/switch'
        super(SwitchSpecificSystemInfo, self).populate()


class Modules(FactsBase):
    '''
    Modules facts class
    '''

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        self._fact_name = 'module_info'
        self._url = '/modules'
        super(Modules, self).populate()


class Default(FactsBase):
    '''
    Default facts class
    '''

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        self._fact_name = 'host_system_info'
        self._url = '/system/status'
        self._stacked_url = '/system/status/global_info'
        super(Default, self).populate()

        self._fact_name = 'switch_specific_system_info'
        self._url = '/system/status/switch'
        super(Default, self).populate()


class PowerSupplies(FactsBase):

    '''
    Power supplies facts class
    '''

    def populate(self):
        '''
        Obtain and populate the facts
        '''
        self._fact_name = 'system_power_supply'
        self._url = '/system/status/power/supply'
        super(PowerSupplies, self).populate()
