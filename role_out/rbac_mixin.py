# Copyright 2016 at&t
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

from oslo_log import log as logging

from tempest import config
from tempest.lib import exceptions
import role_out.test
from tempest.lib import base

CONF = config.CONF

LOG = logging.getLogger(__name__)

class BaseRbacTest(base.BaseTestCase):
    """Contains skip_checks and credentials for all RBAC tests (except Murano)."""

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                '%s skipped as RBAC flag not enabled' % cls.__name__)


class BaseMuranoRbacTest(base.BaseTestCase):
    """Contains skip_checks and credentials for all Murano RBAC tests."""

    credentials = ['alt', 'admin']

    @classmethod
    def skip_checks(cls):
        if 'admin' not in CONF.auth.tempest_roles:
            raise cls.skipException(
                "%s skipped because tempest roles is not admin" % cls.__name__)
        if not CONF.rbac.rbac_flag:
            raise cls.skipException(
                '%s skipped as RBAC flag not enabled' % cls.__name__)
