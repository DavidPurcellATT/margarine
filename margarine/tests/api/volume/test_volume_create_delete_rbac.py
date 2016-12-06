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

from margarine.tests.api import rbac_base as base

from margarine import rbac_exceptions
from margarine import rbac_rule_validation
from margarine.rbac_utils import rbac_utils

from tempest import config

#TODO: DON'T USE TEMPEST.COMMON
from tempest.common import waiters

from margarine import test

from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class CreateDeleteVolumeV2RbacTest(base.BaseVolumeRbacTest):

    def _create_volume(self):
        volume = self.create_volume()
        waiters.wait_for_volume_status(self.volumes_client,
                                       volume['id'], 'available')
        return volume

    @rbac_rule_validation.action(component="Volume", service="cinder",
                                 rule="volume:create")
    @test.idempotent_id('426b08ef-6394-4d06-9128-965d5a6c38ef')
    def test_create_volume(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            # Create a volume
            volume = self._create_volume()
            self.addCleanup(self.volumes_client.delete_volume, volume['id'])
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Volume", service="cinder",
                                 rule="volume:delete")
    @test.idempotent_id('6de9f9c2-509f-4558-867b-af21c7163be4')
    def test_delete_volume(self):
        deleted = False
        # Create a volume
        volume = self._create_volume()

        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            # Delete a volume
            self.volumes_client.delete_volume(volume['id'])
            deleted = True
        except exceptions.NotFound as e:
            raise rbac_exceptions.RbacActionFailed(e)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)
            if not deleted:
                self.addCleanup(self.volumes_client.delete_volume, volume['id'])

class CreateDeleteVolumeV1RbacTest(CreateDeleteVolumeV2RbacTest):
    _api_version = 1

