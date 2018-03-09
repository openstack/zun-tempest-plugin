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


import os

from tempest.test_discover import plugins

from zun_tempest_plugin.tests.tempest import config as config_zun


class ZunTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        base_path += '/../..'
        test_dir = "zun_tempest_plugin/tests/tempest"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        conf.register_opt(config_zun.service_option,
                          group='service_available')
        conf.register_group(config_zun.container_service_group)
        conf.register_opts(config_zun.ContainerServiceGroup,
                           group='container_service')
        conf.register_group(config_zun.docker_group)
        conf.register_opts(config_zun.docker_opts, group='docker')

    def get_opt_lists(self):
        return [(config_zun.container_service_group.name,
                 config_zun.ContainerServiceGroup),
                ('service_available', [config_zun.service_option])]
