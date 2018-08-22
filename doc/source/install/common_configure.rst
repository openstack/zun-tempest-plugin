2. Edit the ``/etc/zun_tempest_plugin/zun_tempest_plugin.conf`` file
and complete the following actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://zun_tempest_plugin:ZUN_TEMPEST_PLUGIN_DBPASS@controller/zun_tempest_plugin
