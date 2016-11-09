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

import logging

from tempest.api.compute import base
from role_out import rbac_rule_validation
from role_out.rbac_utils import rbac_utils

from tempest import config
from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacServicesTestJSON(base.BaseV2ComputeTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(RbacServicesTestJSON, cls).setup_clients()
        cls.admin_client = cls.os_adm.agents_client
        cls.auth_provider = cls.os.auth_provider
        cls.client = cls.services_client

    @classmethod
    def skip_checks(cls):
        super(RbacServicesTestJSON, cls).skip_checks()
        if CONF.auth.tempest_roles != ['admin']:
            print("FFFFFFFFFFFFFFFFF" + CONF.auth.tempest_role)
            raise cls.skipException(
                '%s skipped as tempest roles is not admin' % cls.__name__)
        if not CONF.identity.rbac_flag:
            raise cls.skipException(
                '%s skipped as RBAC flag not enabled' % cls.__name__)
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @test.attr(type='rbac')
    @test.idempotent_id('ec55d455-bab2-4c36-b282-ae3af0efe287')
    @test.requires_ext(extension='os-services', service='compute')
    @rbac_rule_validation.action(
        component="Compute",
        rule="compute_extension:services")
    def test_services_ext(self):
        try:
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.list_services()
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)
