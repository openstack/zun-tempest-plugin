# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest.lib import decorators
from tempest.lib import exceptions

from zun_tempest_plugin.tests.tempest.api import clients
from zun_tempest_plugin.tests.tempest import base


class TestService(base.BaseZunTest):

    credentials = ['primary', 'admin']
    min_microversion = '1.7'

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):

        manager = super(TestService, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        return clients.Manager(manager.credentials)

    @classmethod
    def resource_setup(cls):

        super(TestService, cls).resource_setup()

    # TODO(pksingh): currently functional test doesn't support
    #                policy, will write another test after
    #                implementing policy in functional tests
    @decorators.idempotent_id('a04f61f2-15ae-4200-83b7-1f311b101f36')
    def test_service_list(self):
        self.assertRaises(exceptions.Forbidden,
                          self.container_client.list_services)
