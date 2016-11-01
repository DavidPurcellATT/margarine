
============
Tempest RBAC
============

Tempest RBAC is a set of utilities and direction to test Role Base Access
Control for OpenStack API's.

* Tempest Best Practices: https://wiki.web.att.com/display/CCPdev/Tempest+Best+Practices

Overview
########

The standard Openstack API test does not test RBAC capabilities at all but
focuses on testing API functionality. So we wanted to create a way to test
APIs RBAC while using some of the existing tempest API code base.

Design Principles
#################
Tempest RBAC Design Principles that we strive to live by are:

* Use Python Decorator to handle the exception thrown by roles that
  do not have access to the APIs and treat the exception as an
  expected response.
* Create standard utiliy to handle items like:

  - Switch User roles from admin to the testing role
  - Parse and access data from the rbac_roles.yaml file
* Only test access to the API not the functionality of the API
* Tempest RBAC test should only run if rbac_flag is enabled.
* Tempest test should make sure when the rbac_flag is enabled and
  that the tempest_roles = admin.  This makes sure that the
  credentials that will be used to setup and tear down all test cases
  will have access to perform the necessary actions against the resources.
* Tempest RBAC test should ensure that the tempest standards are followed.

  - Follow Design Principles http://docs.openstack.org/developer/tempest/overview.html
  - Follow Tempest Coding Guide http://docs.openstack.org/developer/tempest/HACKING.html
* All RBAC test case methods should have the following decorators

  - @test.attr(type='rbac')
  - @rbac_rule_validation.action(...)
  - @test.idempotent_id(...) see Test Identification with Idempotent ID
    at http://docs.openstack.org/developer/tempest/HACKING.html

Configuration Information
#########################

tempest.conf
++++++++++++

To run the RBAC tempest api test you have to make the following changes to
the tempest.conf file.

#. [auth] section updates ::

       # Users create for a tempest run will be admin so they have access to all APIs
       tempest_roles = admin

       # Allows test cases to create/destroy tenants and users. This
       # option enables isolated test cases and better parallel
       # execution, but also requires that OpenStack Identity API
       # admin credentials are known. (boolean value)
       allow_tenant_isolation = True

       # Allows test cases to create/destroy projects and users. This option
       # requires that OpenStack Identity API admin credentials are known. If
       # false, isolated test cases and parallel execution, can still be
       # achieved configuring a list of test accounts (boolean value)
       use_dynamic_credentials = False

#. [identity] section updates ::

       # The role that you want the RBAC tests to use for RBAC testing
       rbac_role=_member_
       # Tell standard RBAC test cases to run other wise it they are skipped.
       rbac_flag=true
       # The location of the rbac_roles.yaml file that hold the roles that
       # should be able to call the API.
       rbac_policy_file=/tmp/scripts/rbac_roles.yaml

rbac_roles.yaml
+++++++++++++++

The rbac_roles.yaml file contain a list of roles that are allowed to perform
an action in a service e.g. below is a list of roles that can create a
compute instance
 ::

  Compute:
    compute:create:
      - _member_
      - snapshot_member
      - support_member
      - admin
      - admin_support

The file will contain section for each service it support and actions for
that service.
