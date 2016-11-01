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

import os

from role_out import rbac_auth as auth

from tempest.tests import base

temp_roles_yaml = "Test:\n"\
    "  test:create:\n"\
    "    - role:test_member\n"\
    "    - role:_member_\n"\
    "  test:create2:\n"\
    "    - role:test_member\n"


class RBACAuthTest(base.TestCase):
    def setUp(self):
        super(RBACAuthTest, self).setUp()
        self.rbac_auth = auth.RbacAuthority()

    def test_RBAC_auth_init(self):
        FILENAME = os.path.join(os.path.dirname(__file__),
                                'rbac_roles.yaml')

        temp_roles_file = open(FILENAME, 'w')
        temp_roles_file.write(temp_roles_yaml)
        temp_roles_file.close()

        rbac_auth = auth.RbacAuthority(FILENAME, 'Test')
        self.assertEqual({'test:create':
                          ['role:test_member', 'role:_member_'],
                          'test:create2': ['role:test_member']},
                         rbac_auth.roles_dict)

    def test_RBAC_auth_create_map(self):
        dictionary = {
            'name': 'test_name',
            'id': 'test_id',
        }
        self.rbac_auth.createMap(dictionary)
        self.assertEqual(dictionary, self.rbac_auth.roles_dict)

    def test_RBAC_auth_get_permission_empty_roles(self):
        self.rbac_auth.roles_dict = None
        self.assertRaises(StandardError, self.rbac_auth.get_permission, "", "")

    def test_RBAC_auth_get_permission_role_in_api(self):
        self.rbac_auth.roles_dict = {'api': ['_member_']}
        self.assertTrue(self.rbac_auth.get_permission("api", "_member_"))

    def test_RBAC_auth_get_permission_role_not_in_api(self):
        self.rbac_auth.roles_dict = {'api': ['_member_']}
        self.assertFalse(self.rbac_auth.get_permission("api",
                                                       "support_member"))

    def test_RBAC_auth_get_permission_no_api(self):
        self.rbac_auth.roles_dict = {}
        self.assertRaises(KeyError, self.rbac_auth.get_permission,
                          "api", "support_member")

    def test_RBAC_auth_role_parser_create(self):
        FILENAME = os.path.join(os.path.dirname(__file__),
                                'rbac_roles.yaml')

        temp_roles_file = open(FILENAME, 'w')
        temp_roles_file.write(temp_roles_yaml)
        temp_roles_file.close()

        auth.RoleParser(FILENAME)
        self.assertEqual(
            [{'Test': {'test:create':
                       ['role:test_member', 'role:_member_'],
                       'test:create2': ['role:test_member']}}],
            auth.RoleParser.Inner._rbac_map
        )

    def test_RBAC_auth_role_parser_parse(self):
        auth.RoleParser.Inner._rbac_map = [
            {'Test': {'test:create': ['role:test_member', 'role:_member_'],
                      'test:create2': ['role:test_member']}}
        ]

        self.assertEqual({'test:create2': ['role:test_member'],
                          'test:create': ['role:test_member',
                                          'role:_member_']},
                         auth.RoleParser.parse("Test"))

    def test_RBAC_auth_role_parser_parse_fail(self):
        auth.RoleParser.Inner._rbac_map = [
            {'Test': {'test:create': ['role:test_member', 'role:_member_'],
                      'test:create2': ['role:test_member']}}
        ]

        self.assertIsNone(auth.RoleParser.parse("FAILURE"))

