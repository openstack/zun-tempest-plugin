#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from tempest import config
from tempest.lib.common import api_version_utils
from tempest import test

from zun_tempest_plugin.tests.tempest.api import api_microversion_fixture

CONF = config.CONF


class BaseZunTest(api_version_utils.BaseMicroversionTest,
                  test.BaseTestCase):

    credentials = ['primary']

    @classmethod
    def skip_checks(cls):
        super(BaseZunTest, cls).skip_checks()
        if not CONF.service_available.zun:
            skip_msg = 'Zun is disabled'
            raise cls.skipException(skip_msg)
        cfg_min_version = CONF.container_management.min_microversion
        cfg_max_version = CONF.container_management.max_microversion
        api_version_utils.check_skip_with_microversion(cls.min_microversion,
                                                       cls.max_microversion,
                                                       cfg_min_version,
                                                       cfg_max_version)

    @classmethod
    def setup_clients(cls):
        super(BaseZunTest, cls).setup_clients()
        pass

    @classmethod
    def setup_credentials(cls):
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.container_management.min_microversion
            ))
        cls.services_microversion = {
            CONF.container_management.catalog_type: cls.request_microversion}
        super(BaseZunTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(BaseZunTest, cls).resource_setup()
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.container_management.min_microversion))
        cls.wait_timeout = CONF.container_management.wait_timeout

    def setUp(self):
        super(BaseZunTest, self).setUp()
        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            self.request_microversion
        ))
