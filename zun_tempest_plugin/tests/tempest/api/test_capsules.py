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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from zun_tempest_plugin.tests.tempest.api import clients
from zun_tempest_plugin.tests.tempest.api.common import datagen
from zun_tempest_plugin.tests.tempest import base


class TestCapsule(base.BaseZunTest):

    credentials = ['primary', 'admin']
    min_microversion = '1.12'

    @classmethod
    def tearDownClass(cls):
        cls.cleanup_network()
        super(TestCapsule, cls).tearDownClass()

    @classmethod
    def cleanup_network(cls):
        creds_provider = cls._get_credentials_provider()
        creds = creds_provider.get_primary_creds()
        network = getattr(creds, 'network', None)
        if not network:
            return

        docker_base_url = cls._get_docker_url()
        networks = cls.docker_client.list_networks(
            network['id'], docker_auth_url=docker_base_url)
        for network in networks:
            cls.docker_client.remove_network(
                network['Id'], docker_auth_url=docker_base_url)

    @classmethod
    def _get_docker_url(cls, host='localhost'):
        protocol = 'tcp'
        port = '2375'
        base_url = '%s://%s:%s' % (protocol, host, port)
        return base_url

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(TestCapsule, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        return clients.Manager(manager.credentials)

    @classmethod
    def setup_clients(cls):
        super(TestCapsule, cls).setup_clients()
        cls.container_client = cls.os_primary.container_client
        cls.docker_client = clients.DockerClient()
        cls.images_client = cls.os_primary.images_client
        cls.ports_client = cls.os_primary.ports_client
        cls.sgs_client = cls.os_primary.sgs_client

    @classmethod
    def resource_setup(cls):
        super(TestCapsule, cls).resource_setup()

    def setUp(self):
        super(TestCapsule, self).setUp()
        self.capsules = []

    def tearDown(self):
        super(TestCapsule, self).tearDown()

    @decorators.idempotent_id('d5c91423-0f83-44f8-8228-e6a28ef7817e')
    def test_create_capsule(self):
        self._create_capsule()

    def _create_capsule(self, **kwargs):
        gen_model = datagen.capsule_data(**kwargs)
        resp, model = self.container_client.post_capsule(gen_model)
        self.addCleanup(self.container_client.delete_capsule, model.uuid)
        self.capsules.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to finish creation
        self.container_client.ensure_capsule_in_desired_state(
            model.uuid, 'Running')

        # Assert the capsule is created
        resp, model = self.container_client.get_capsule(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertEqual('Running', model.status)
        # TODO(hongbin): verify all containers are running
        return resp, model

    @decorators.idempotent_id('b7e79a0b-c09e-4539-886f-a9f33ae15620')
    def test_create_capsule_full(self):
        capsule_data = {
            "template": {
                "capsuleVersion": "beta",
                "kind": "capsule",
                "metadata": {
                    "labels": {
                        "app": "web",
                        "app1": "web1"
                    },
                    "name": data_utils.rand_name('capsule')
                },
                "spec": {
                    "restartPolicy": "Always",
                    "containers": [
                        {
                            "command": [
                                "/bin/bash"
                            ],
                            "env": {
                                "ENV1": "/usr/local/bin",
                                "ENV2": "/usr/bin"
                            },
                            "image": "ubuntu",
                            "imagePullPolicy": "ifnotpresent",
                            "ports": [
                                {
                                    "containerPort": 80,
                                    "hostPort": 80,
                                    "name": "nginx-port",
                                    "protocol": "TCP"
                                }
                            ],
                            "resources": {
                                "requests": {
                                    "cpu": 1,
                                    "memory": 256
                                }
                            },
                            "workDir": "/root"
                        }
                    ]
                }
            }
        }

        self._create_capsule(data=capsule_data)
