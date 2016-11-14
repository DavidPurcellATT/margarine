# Copyright 2017 at&t
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

from role_out import rbac_rule_validation
from role_out.rbac_utils import rbac_utils
from tempest.common.utils import data_utils

from tempest.api.compute import base
from tempest.api.identity import base as identity_base
from tempest import config

from tempest import test

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)

class RBACAbsoluteLimitsTestJSON(base.BaseV2ComputeTest):

    credentials = ['admin', 'primary']

    @classmethod
    def setup_clients(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).setup_clients()
        cls.identity_client = cls.os_adm.identity_client
        cls.tenants_client = cls.os_adm.tenants_client
        cls.admin_client = cls.os_admin.agents_client
        cls.auth_provider = cls.os.auth_provider
        cls.client = cls.os.limits_client

    @classmethod
    def resource_setup(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).resource_setup()
	cls.tenants = []

    @classmethod
    def skip_checks(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).skip_checks()
        if CONF.auth.tempest_roles != ['admin']:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                '%s skipped as RBAC flag not enabled' % cls.__name__)
        if not CONF.compute_feature_enabled.api_extensions:
            raise cls.skipException(
                '%s skipped as no compute extensions enabled' % cls.__name__)

    @test.attr(type='rbac')
    @rbac_rule_validation.action(component="Compute", rule="compute_extension:"
                                           "used_limits_for_admin")
    @test.idempotent_id('3fb60f83-9a5f-4fdd-89d9-26c3710844a1')
    def test_used_limits_for_admin_rbac(self):
        tenant_name = data_utils.rand_name(name='tenant')
        body = self.tenants_client.create_tenant(name=tenant_name)['tenant']
        tenant = body
        self.tenants.append(tenant)
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            temp = self.client.show_limits()
	    print(temp)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)
            self.tenants_client.delete_tenant(tenant['id'])
            self.tenants.remove(tenant)

