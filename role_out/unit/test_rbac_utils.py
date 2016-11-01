# Copyright 2016 AT&T Inc.
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

import json
import mock

from tempest.common.rbac import rbac_utils as utils

from tempest.tests import base


class RBACUtilsTest(base.TestCase):
    def setUp(self):
        super(RBACUtilsTest, self).setUp()
        self.rbac_utils = utils.RbacUtils

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_get_roles_none(self, requests, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        response = mock.Mock()
        response.status_code = 200
        response.text = json.dumps({'roles': []})
        requests.get.return_value = response
        self.assertEqual({'admin_role_id': None, 'rbac_role_id': None},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_get_roles_member(self, requests, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        response = mock.Mock()
        response.status_code = 200
        response.text = json.dumps({'roles': [{'name': '_member_',
                                    'id': '_member_id'}]})
        requests.get.return_value = response

        config.identity.rbac_role = '_member_'

        self.assertEqual({'admin_role_id': None,
                          'rbac_role_id': '_member_id'},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_get_roles_admin(self, requests, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        response = mock.Mock()
        response.status_code = 200
        response.text = json.dumps({'roles': [{'name': 'admin',
                                    'id': 'admin_id'}]})
        requests.get.return_value = response

        config.identity.rbac_role = 'admin'

        self.assertEqual({'admin_role_id': 'admin_id',
                          'rbac_role_id': 'admin_id'},
                         self.rbac_utils.get_roles(caller))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_get_roles_admin_not_role(self, requests, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        response = mock.Mock()
        response.status_code = 200
        response.text = json.dumps(
            {'roles': [{'name': 'admin', 'id': 'admin_id'}]}
        )
        requests.get.return_value = response

        self.assertEqual({'admin_role_id': 'admin_id', 'rbac_role_id': None},
                         self.rbac_utils.get_roles(caller))

    def test_RBAC_utils_get_existing_roles(self):
        self.rbac_utils.dictionary = {'admin_role_id': None,
                                      'rbac_role_id': None}

        self.assertEqual({'admin_role_id': None, 'rbac_role_id': None},
                         self.rbac_utils.get_roles(None))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_get_roles_response_404(self, requests, config):
        self.rbac_utils.dictionary = {}

        caller = mock.Mock()
        caller.admin_client.token = "test_token"

        response = mock.Mock()
        response.status_code = 404
        response.text = json.dumps({'roles': []})
        requests.get.return_value = response

        self.assertRaises(StandardError, self.rbac_utils.get_roles, caller)

    def test_RBAC_utils_switch_roles_none(self):
        self.assertIsNone(self.rbac_utils.switch_role(None))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.RbacUtils.get_roles')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_switch_roles_member(self, requests,
                                            get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        response_204 = mock.Mock()
        response_204.status_code = 204

        response_200 = mock.Mock()
        response_200.status_code = 200
        response_200.text = json.dumps({'roles': [{'id': 'id'}]})

        requests.put.side_effect = None
        requests.put.return_value = response_204
        requests.delete.return_value = response_204
        requests.get.return_value = response_200

        self.assertIsNone(self.rbac_utils.switch_role(self, "_member_"))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.RbacUtils.get_roles')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_switch_roles_false(self, requests,
                                           get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        response_204 = mock.Mock()
        response_204.status_code = 204

        response_200 = mock.Mock()
        response_200.status_code = 200
        response_200.text = json.dumps({'roles': [{'id': 'id'}]})

        requests.put.side_effect = None
        requests.put.return_value = response_204
        requests.delete.return_value = response_204
        requests.get.return_value = response_200

        self.assertIsNone(self.rbac_utils.switch_role(self, False))

    @mock.patch('tempest.common.rbac.rbac_utils.CONF')
    @mock.patch('tempest.common.rbac.rbac_utils.RbacUtils.get_roles')
    @mock.patch('tempest.common.rbac.rbac_utils.requests')
    def test_RBAC_utils_switch_roles_get_roles_fails(self, requests,
                                                     get_roles, config):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}

        self.auth_provider = mock.Mock()
        self.auth_provider.credentials.user_id = "user_id"
        self.auth_provider.credentials.tenant_id = "tenant_id"
        self.admin_client = mock.Mock()
        self.admin_client.token = "admin_token"

        response_204 = mock.Mock()
        response_204.status_code = 204

        response_200 = mock.Mock()
        response_200.status_code = 404
        response_200.text = json.dumps({'roles': [{'id': 'id'}]})

        requests.put.side_effect = None
        requests.put.return_value = response_204
        requests.delete.return_value = response_204
        requests.get.return_value = response_200

        self.assertRaises(StandardError, self.rbac_utils.switch_role, self,
                          False)

    @mock.patch('tempest.common.rbac.rbac_utils.RbacUtils.get_roles')
    def test_RBAC_utils_switch_roles_exception(self, get_roles):
        get_roles.return_value = {'admin_role_id': None,
                                  'rbac_role_id': '_member_id'}
        self.assertRaises(AttributeError, self.rbac_utils.switch_role,
                          self, "admin")

