========================
Team and repository tags
========================

.. image:: http://governance.openstack.org/tc/badges/zun-tempest-plugin.svg
    :target: http://governance.openstack.org/tc/reference/tags/index.html

==========================
Tempest Integration of Zun
==========================

This directory contains Tempest tests to cover the Zun project, as well
as a plugin to automatically load these tests into tempest.

See the Tempest plugin docs for information on using it:
https://docs.openstack.org/tempest/latest/#using-plugins

* Free software: Apache license
* Documentation: https://docs.openstack.org/zun-tempest-plugin/latest
* Source: https://opendev.org/openstack/zun-tempest-plugin
* Bugs: https://bugs.launchpad.net/zun

Running the tests
-----------------

Edit ``/opt/stack/tempest/etc/tempest.conf``:

   * Add the ``[container_service]`` section,
     configure ``min_microversion`` and ``max_microversion``:

     .. code-block:: ini

        [container_service]
        min_microversion=1.32
        max_microversion=1.32

   .. note::

      You might need to modify the min/max microversion based on your
      test environment.

To run all tests from this plugin, install Zun into your environment and
navigate to tempest directory::

    $ cd /opt/stack/tempest

Run this command::

    $ tempest run --regex zun_tempest_plugin.tests.tempest.api

To run a single test case, run with the test case name, for example::

    $ tempest run --regex zun_tempest_plugin.tests.tempest.api.test_containers.TestContainer.test_list_containers
