#
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

import socket

from oslo_config import cfg

service_option = cfg.BoolOpt("zun",
                             default=True,
                             help="Whether or not zun is expected to be "
                                  "available")

container_management_group = cfg.OptGroup(
    name="container_management", title="Container Management Service Options")

ContainerManagementGroup = [
    cfg.StrOpt("catalog_type",
               default="container",
               help="Catalog type of the container management service."),
    cfg.IntOpt("wait_timeout",
               default=60,
               help="Waiting time for a specific status, in seconds."),
    cfg.StrOpt('min_microversion',
               default=None,
               help="Lower version of the test target microversion range. "
                    "The format is 'X.Y', where 'X' and 'Y' are int values. "
                    "Tempest selects tests based on the range between "
                    "min_microversion and max_microversion. If both values "
                    "are None, Tempest avoids tests which require a "
                    "microversion."),
    cfg.StrOpt('max_microversion',
               default='latest',
               help="Upper version of the test target microversion range. "
                    "The format is 'X.Y'. where 'X' and 'Y' are int values. "
                    "Tempest selects tests based on the range between "
                    "microversion and max_microversion. If both values "
                    "are None, Tempest avoids tests which require a "
                    "microversion.")
]

docker_group = cfg.OptGroup(name='docker',
                            title='Options for docker')

docker_opts = [
    cfg.StrOpt('docker_remote_api_version',
               default='1.26',
               help='Docker remote api version. Override it according to '
                    'specific docker api version in your environment.'),
    cfg.IntOpt('default_timeout',
               default=60,
               help='Default timeout in seconds for docker client '
                    'operations.'),
    cfg.StrOpt('api_url',
               default='unix:///var/run/docker.sock',
               help='API endpoint of docker daemon'),
    cfg.StrOpt('docker_remote_api_url',
               default='tcp://$docker_remote_api_host:$docker_remote_api_port',
               help='Remote API endpoint of docker daemon'),
    cfg.StrOpt('docker_remote_api_host',
               default=socket.gethostname(),
               sample_default='localhost',
               help='Defines the remote api host for the docker daemon.'),
    cfg.StrOpt('docker_remote_api_port',
               default='2375',
               help='Defines the remote api port for the docker daemon.'),
]
