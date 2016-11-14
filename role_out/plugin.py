# Copyright (c) 2016 AT&T Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from tempest import config
from tempest.test_discover import plugins
from role_out import config as config_share


class RoleOutPlugin(plugins.TempestPlugin):
    #TODO: Learn what this is / does.
    def get_opt_lists(self):
        return []

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "role_out/tests"
        full_test_dir = os.path.join(base_path, test_dir)
	print(full_test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        config.register_opt_group(
            conf,
            config_share.rbac_group,
            config_share.RbacGroup)
