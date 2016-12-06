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

from margarine import rbac_rule_validation
from margarine.rbac_utils import rbac_utils
from tempest.lib.common.utils import data_utils

from margarine.tests.api import rbac_base

from tempest import config

from tempest.lib import decorators

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacAbsoluteLimitsTestJSON(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(RbacAbsoluteLimitsTestJSON, cls).setup_clients()
        cls.identity_client = cls.os_adm.identity_client
        cls.tenants_client = cls.os_adm.tenants_client
        cls.admin_client = cls.os_admin.agents_client
        cls.client = cls.os.limits_client

    @classmethod
    def resource_setup(cls):
        super(RBACAbsoluteLimitsTestJSON, cls).resource_setup()
        cls.tenants = []

    @rbac_rule_validation.action(component="Compute", service='nova',
                                 rule="compute_extension:"
                                 "used_limits_for_admin")
    @decorators.idempotent_id('3fb60f83-9a5f-4fdd-89d9-26c3710844a1')
    def test_used_limits_for_admin_rbac(self):
        tenant_name = data_utils.rand_name(name='tenant')
        body = self.tenants_client.create_tenant(name=tenant_name)['tenant']
        tenant = body
        self.tenants.append(tenant)
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.show_limits()
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)
            self.tenants_client.delete_tenant(tenant['id'])
            self.tenants.remove(tenant)
