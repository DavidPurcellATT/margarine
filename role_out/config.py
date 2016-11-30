from oslo_config import cfg

rbac_group = cfg.OptGroup(name='rbac',
                          title='RBAC testing options')

RbacGroup = [
    cfg.StrOpt('rbac_role',
               default='admin',
               help="RBAC role."),
    cfg.BoolOpt('rbac_flag',
                default=False,
                help="Consider RBAC testing, if it is set to True "),
    cfg.StrOpt('rbac_policy_file',
               help="RBAC Policy YAML File Path"),
]
