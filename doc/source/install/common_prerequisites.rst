Prerequisites
-------------

Before you install and configure the openstack service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``zun_tempest_plugin`` database:

     .. code-block:: none

        CREATE DATABASE zun_tempest_plugin;

   * Grant proper access to the ``zun_tempest_plugin`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON zun_tempest_plugin.* TO 'zun_tempest_plugin'@'localhost' \
          IDENTIFIED BY 'ZUN_TEMPEST_PLUGIN_DBPASS';
        GRANT ALL PRIVILEGES ON zun_tempest_plugin.* TO 'zun_tempest_plugin'@'%' \
          IDENTIFIED BY 'ZUN_TEMPEST_PLUGIN_DBPASS';

     Replace ``ZUN_TEMPEST_PLUGIN_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``zun_tempest_plugin`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt zun_tempest_plugin

   * Add the ``admin`` role to the ``zun_tempest_plugin`` user:

     .. code-block:: console

        $ openstack role add --project service --user zun_tempest_plugin admin

   * Create the zun_tempest_plugin service entities:

     .. code-block:: console

        $ openstack service create --name zun_tempest_plugin --description "openstack" openstack

#. Create the openstack service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        openstack public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        openstack internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        openstack admin http://controller:XXXX/vY/%\(tenant_id\)s
