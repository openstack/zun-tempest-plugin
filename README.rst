========================
Team and repository tags
========================

.. image:: http://governance.openstack.org/badges/zun-tempest-plugin.svg
    :target: http://governance.openstack.org/reference/tags/index.html

==========================
Tempest Integration of Zun
==========================

This directory contains Tempest tests to cover the Zun project, as well
as a plugin to automatically load these tests into tempest.

See the Tempest plugin docs for information on using it:
https://docs.openstack.org/tempest/latest/#using-plugins

* Free software: Apache license
* Documentation: https://docs.openstack.org/zun-tempest-plugin/latest
* Source: https://git.openstack.org/cgit/openstack/zun-tempest-plugin
* Bugs: https://bugs.launchpad.net/zun

Running the tests
-----------------

To run all tests from this plugin, install Zun into your environment and
navigate to tempest directory::

    $ cd /opt/stack/tempest

Run this command::

    $ tox -e all-plugin -- zun_tempest_plugin.tests.tempest.api

To run a single test case, run with the test case name, for example::

    $ tox -e all-plugin -- zun_tempest_plugin.tests.tempest.api.test_containers.test_list_containers
