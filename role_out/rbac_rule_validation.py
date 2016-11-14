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

import rbac_auth
import rbac_exceptions
from tempest import config

from tempest.lib import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def action(component, rule):
    def decorator(func):
        def wrapper(*args, **kwargs):
            authority = rbac_auth.RbacAuthority(
                CONF.rbac.rbac_policy_file, component)
            allowed = authority.get_permission(rule, CONF.rbac.rbac_role)
            try:
                func(*args)
            except exceptions.Forbidden as e:
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (CONF.rbac.rbac_role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s exception was: %s" %
                        (msg, e))
            except exceptions.Unauthorized as e:
                if allowed:
                    msg = "UNAUTHORIZED"
		    raise exceptions.Unauthorized(msg,e)
            except rbac_exceptions.RbacActionFailed as e:
                if allowed:
                    msg = ("Role %s was not allowed to perform %s." %
                           (CONF.rbac.rbac_role, rule))
                    LOG.error(msg)
                    raise exceptions.Forbidden(
                        "%s RbacActionFailed was: %s" %
                        (msg, e))
            else:
                if not allowed:
                    LOG.error("Role %s was allowed to perform %s" %
                              (CONF.rbac.rbac_role, rule))
                    raise StandardError(
                        "OverPermission: Role %s was allowed to perform %s" %
                        (CONF.rbac.rbac_role, rule))
        return wrapper
    return decorator
