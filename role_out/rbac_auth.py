# Copyright 2016 AT&T Corp
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import yaml

from oslo_log import log as logging

from tempest.lib import exceptions

LOG = logging.getLogger(__name__)


class RoleParser(object):
    _inner = None

    class Inner(object):
        _rbac_map = None

        def __init__(self, filepath):
            with open(filepath) as f:
                RoleParser.Inner._rbac_map = list(yaml.safe_load_all(f))
                f.close()

    def __init__(self, filepath):
        if RoleParser._inner is None:
            RoleParser._inner = RoleParser.Inner(filepath)

    @staticmethod
    def parse(component):
        try:
            for section in RoleParser.Inner._rbac_map:
                if component in section:
                    return section[component]
        except yaml.parser.ParserError:
            LOG.error("Error while parsing roles yaml file. Did you pass a "
                      "valid component name from the test case?")
        return None


class RbacAuthority(object):
    def __init__(self, filepath=None, component=None):
        if filepath is not None and component is not None:
            self.roles_dict = RoleParser(filepath).parse(component)

    def createMap(self, dictionary):
        self.roles_dict = dictionary

    def get_permission(self, api, role):
        if self.roles_dict is None:
            raise exceptions.InvalidConfiguration("Roles dictionary is empty!")
        try:
            _api = self.roles_dict[api]
            if role in _api:
                LOG.debug("[API]: %s, [Role]: %s is allowed!", api, role)
                return True
            else:
                LOG.debug("[API]: %s, [Role]: %s  is NOT allowed!", api, role)
                return False
        except KeyError:
            raise KeyError("'%s' API is not defined in the master data file"
                           % api)
        return False

