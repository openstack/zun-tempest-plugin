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

from io import BytesIO
import tarfile
import time
import types

from oslo_serialization import jsonutils as json
from oslo_utils import encodeutils
import six
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from zun_tempest_plugin.tests.tempest.api import clients
from zun_tempest_plugin.tests.tempest.api.common import datagen
from zun_tempest_plugin.tests.tempest import base
from zun_tempest_plugin.tests.tempest import utils


class TestContainer(base.BaseZunTest):

    credentials = ['primary', 'admin']
    min_microversion = '1.20'

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(TestContainer, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        return clients.Manager(manager.credentials)

    @classmethod
    def setup_clients(cls):
        super(TestContainer, cls).setup_clients()
        cls.images_client = cls.os_primary.images_client
        cls.sgs_client = cls.os_primary.sgs_client
        cls.vol_client = cls.os_primary.vol_client

    @classmethod
    def resource_setup(cls):
        super(TestContainer, cls).resource_setup()

    def setUp(self):
        super(TestContainer, self).setUp()
        self.containers = []

    def tearDown(self):
        _, model = self.os_admin.container_client.list_containers(
            params={'all_projects': True})
        for c in model.containers:
            if c['uuid'] in self.containers:
                # NOTE(kiennt): From version 1.7, Zun disallowed non-admin
                #               users to force delete containers. Therefore,
                #               we have to be admin to do this action.
                self.os_admin.container_client.delete_container(
                    c['uuid'],
                    params={'stop': True, 'all_projects': True})
                self.container_client.ensure_container_deleted(c['uuid'])

        super(TestContainer, self).tearDown()

    @decorators.idempotent_id('b8946b8c-57d5-4fdc-a09a-001d6b552725')
    def test_create_container(self):
        self._create_container()

    @decorators.idempotent_id('b3e307d4-844b-4a57-8c60-8fb3f57aea7c')
    def test_list_containers(self):
        _, container = self._create_container()
        resp, model = self.container_client.list_containers()
        self.assertEqual(200, resp.status)
        self.assertGreater(len(model.containers), 0)
        self.assertIn(
            container.uuid,
            list([c['uuid'] for c in model.containers]))

    @decorators.idempotent_id('0dd13c28-c5ff-4b9e-b73b-61185b410de4')
    def test_get_container(self):
        _, container = self._create_container()
        resp, model = self.container_client.get_container(container.uuid)
        self.assertEqual(200, resp.status)
        self.assertEqual(container.uuid, model.uuid)

    @decorators.idempotent_id('cef53a56-22b7-4808-b01c-06b2b7126115')
    def test_delete_container(self):
        _, container = self._create_container()
        docker_url = self._get_docker_url(container)
        resp, _ = self.container_client.delete_container(container.uuid)
        self.assertEqual(204, resp.status)
        self.container_client.ensure_container_deleted(container.uuid)
        container = self.docker_client.get_container(
            container.uuid, docker_url)
        self.assertIsNone(container)

    @decorators.idempotent_id('ef69c9e7-0ce0-4e14-b7ec-c1dc581a3927')
    def test_run_container(self):
        self._run_container()

    @decorators.idempotent_id('a2152d78-b6a6-4f47-8767-d83d29c6fb19')
    def test_run_container_with_minimal_params(self):
        gen_model = datagen.container_data({'image': 'nginx'})
        self._run_container(gen_model=gen_model)

    @decorators.idempotent_id('c32f93e3-da88-4c13-be38-25d2e662a28e')
    def test_run_container_with_image_driver_glance(self):
        docker_base_url = self._get_docker_url()
        self.docker_client.pull_image(
            'cirros', docker_auth_url=docker_base_url)
        image_data = self.docker_client.get_image(
            'cirros', docker_base_url)
        if isinstance(image_data, types.GeneratorType):
            # NOTE(kiennt): In Docker-py 3.1.0, get_image
            #               returns generator [1]. These lines
            #               makes image_data readable.
            # [1] https://bugs.launchpad.net/zun/+bug/1753080
            image_data = six.b('').join(image_data)
            image_data = six.BytesIO(image_data)

        image = self.images_client.create_image(
            name='cirros', disk_format='raw', container_format='docker')
        self.addCleanup(self.images_client.delete_image, image['id'])
        self.images_client.store_image_file(image['id'], image_data)
        # delete the local image that was previously pulled down
        self.docker_client.delete_image('cirros', docker_base_url)

        _, model = self._run_container(
            image='cirros', image_driver='glance')

    @decorators.idempotent_id('b70bedbc-5ba2-400c-8f5f-0cf05ca17151')
    def test_run_container_with_environment(self):
        _, model = self._run_container(environment={
            'key1': 'env1', 'key2': 'env2'})

        container = self.docker_client.get_container(
            model.uuid,
            self._get_docker_url(model))
        env = container.get('Config').get('Env')
        self.assertTrue('key1=env1' in env)
        self.assertTrue('key2=env2' in env)

    @decorators.idempotent_id('0e59d549-58ff-440f-8704-10e223c31cbc')
    def test_run_container_with_labels(self):
        _, model = self._run_container(labels={
            'key1': 'label1', 'key2': 'label2'})

        container = self.docker_client.get_container(
            model.uuid,
            self._get_docker_url(model))
        labels = container.get('Config').get('Labels')
        self.assertEqual({'key1': 'label1', 'key2': 'label2'}, labels)

    @decorators.idempotent_id('8fc7fec1-e1a2-3f65-a5a6-dba425c1607c')
    def test_run_container_with_port(self):
        project_id = self.container_client.tenant_id
        networks = self.networks_client.list_networks()['networks']
        for network in networks:
            if network['project_id'] == project_id:
                tenant_network = network
                break
        else:
            self.fail('Cannot find network in tenant.')

        port = self.create_port(tenant_network)
        port_address = port['fixed_ips'][0]['ip_address']
        port_subnet = port['fixed_ips'][0]['subnet_id']

        _, model = self._run_container(nets=[{'port': port['id']}])
        address = {'port': port['id'],
                   'addr': port_address,
                   'subnet_id': port_subnet}
        self._assert_container_has_address(model, address,
                                           network_id=tenant_network['id'])

    @decorators.idempotent_id('cfa24356-30fd-42b7-92c7-bbf01bcaf6eb')
    def test_run_container_with_port_in_dual_net(self):
        network = self.create_network()
        _, subnetv4 = self._create_v4_subnet_and_pool(network)
        _, subnetv6 = self._create_v6_subnet_and_pool(network)
        port = self.create_port(network)
        ipv4_address = None
        ipv6_address = None
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['subnet_id'] == subnetv4['id']:
                ipv4_address = fixed_ip['ip_address']
            elif fixed_ip['subnet_id'] == subnetv6['id']:
                ipv6_address = fixed_ip['ip_address']
        self.assertIsNotNone(ipv4_address)
        self.assertIsNotNone(ipv6_address)

        _, model = self._run_container(nets=[{'port': port['id']}])

        self.assertEqual(2, len(model.addresses[network['id']]))
        address = {'port': port['id'],
                   'addr': ipv4_address,
                   'subnet_id': subnetv4['id'],
                   'version': 4}
        self._assert_container_has_address(model, address)
        address = {'port': port['id'],
                   'addr': ipv6_address,
                   'subnet_id': subnetv6['id'],
                   'version': 6}
        self._assert_container_has_address(model, address)

        # create an ipv4 port from dual net
        port = self.create_port(network,
                                fixed_ips=[{'subnet_id': subnetv4['id']}])
        _, model = self._run_container(nets=[{'port': port['id']}])
        self.assertEqual(1, len(model.addresses[network['id']]))
        address = {'port': port['id'],
                   'addr': port['fixed_ips'][0]['ip_address'],
                   'subnet_id': subnetv4['id'],
                   'version': 4}
        self._assert_container_has_address(model, address)

    def _assert_container_has_address(self, container, address,
                                      network_id=None):
        self.assertLessEqual(1, len(container.addresses))
        if network_id is None:
            network_id = list(container.addresses.keys())[0]
        self.assertIn(network_id, container.addresses)
        for addr in container.addresses[network_id]:
            if six.viewitems(address) <= six.viewitems(addr):
                break
        else:
            self.fail('Address %s is not found in container %s.' %
                      (address, container))

    def _create_v4_subnet_and_pool(self, network, subnet_values=None,
                                   pool_values=None):
        pool_kwargs = {'prefixes': [u'10.11.12.0/24'],
                       'min_prefixlen': '28'}
        if pool_values:
            pool_kwargs.update(pool_values)
        created_subnetpool = self.create_subnetpool(**pool_kwargs)
        pool_id = created_subnetpool['id']

        subnet_kwargs = {'subnetpool_id': pool_id,
                         'ip_version': 4}
        if subnet_values:
            subnet_kwargs.update(subnet_values)
        subnet = self.create_subnet(network, **subnet_kwargs)
        return pool_id, subnet

    def _create_v6_subnet_and_pool(self, network, subnet_values=None,
                                   pool_values=None):
        pool_kwargs = {'prefixes': [u'2001:db8:3::/48'],
                       'min_prefixlen': '64'}
        if pool_values:
            pool_kwargs.update(pool_values)
        created_subnetpool = self.create_subnetpool(**pool_kwargs)
        pool_id = created_subnetpool['id']

        subnet_kwargs = {'subnetpool_id': pool_id,
                         'ip_version': 6}
        if subnet_values:
            subnet_kwargs.update(subnet_values)
        subnet = self.create_subnet(network, **subnet_kwargs)
        return pool_id, subnet

    @decorators.idempotent_id('9fc7fec0-e1a9-4f65-a5a6-dba425c1607c')
    def test_run_container_with_restart_policy(self):
        _, model = self._run_container(restart_policy={
            'Name': 'on-failure', 'MaximumRetryCount': 2})

        container = self.docker_client.get_container(
            model.uuid,
            self._get_docker_url(model))
        policy = container.get('HostConfig').get('RestartPolicy')
        self.assertEqual('on-failure', policy['Name'])
        self.assertEqual(2, policy['MaximumRetryCount'])

    @decorators.idempotent_id('58585a4f-cdce-4dbd-9741-4416d1098f94')
    def test_run_container_with_interactive(self):
        _, model = self._run_container(interactive=True)

        container = self.docker_client.get_container(
            model.uuid,
            self._get_docker_url(model))
        tty = container.get('Config').get('Tty')
        stdin_open = container.get('Config').get('OpenStdin')
        self.assertIs(True, tty)
        self.assertIs(True, stdin_open)

    @decorators.idempotent_id('f181eeda-a9d1-4b2e-9746-d6634ca81e2f')
    @utils.requires_microversion('1.20')
    def test_run_container_without_security_groups(self):
        gen_model = datagen.container_data()
        delattr(gen_model, 'security_groups')
        _, model = self._run_container(gen_model=gen_model)
        sgs = self._get_all_security_groups(model)
        self.assertEqual(1, len(sgs))
        self.assertEqual('default', sgs[0])

    @decorators.idempotent_id('f181eeda-a9d1-4b2e-9746-d6634ca81e2f')
    def test_run_container_with_security_groups(self):
        sg_name = data_utils.rand_name('test_sg')
        sg = self.sgs_client.create_security_group(name=sg_name)
        self.addCleanup(self.sgs_client.delete_security_group,
                        sg['security_group']['id'])
        _, model = self._run_container(security_groups=[sg_name])
        sgs = self._get_all_security_groups(model)
        self.assertEqual(1, len(sgs))
        self.assertEqual(sg_name, sgs[0])

    @decorators.idempotent_id('f55dbe0d-3e8a-4798-9267-c9b13361e721')
    def test_run_container_with_network(self):
        """Test container run with the given network

        This test does the following:
        1. Create a network and its subnet
        2. Verity the created network and its subnet.
        3. Run a container with this network.
        4. Verify container's addresses is in subnet's cidr.
        """
        test_net = self.create_network(name='test_net')
        self.assertEqual(test_net['name'], 'test_net')
        test_subnet = self.create_subnet(
            test_net, name='test_subnet', cidr='10.1.0.0/24')
        self.assertEqual(test_subnet['name'], 'test_subnet')
        self.assertEqual(test_subnet['cidr'], '10.1.0.0/24')
        _, model = self._run_container(nets=[{'network': test_net['id']}])
        self.assertEqual(1, len(model.addresses))
        subnet_id = list(model.addresses.values())[0][0]['subnet_id']
        addr = list(model.addresses.values())[0][0]['addr']
        self.assertEqual(subnet_id, test_subnet['id'])
        self.assertIn('10.1.0', addr)

    @decorators.idempotent_id('2bc86759-ffca-4b3d-bf25-4cf260a67704')
    def test_run_container_with_shared_network(self):
        """Test container run with the given shared network

        This test does the following:
        1. Create a network and its subnet (In admin tenant)
        2. Verity the created network and its subnet.
        3. Run a container with this network.
        4. Verify container's addresses is in subnet's cidr.
        """
        test_net = self.create_network(
            client=self.os_admin.neutron_client,
            name='test_net', shared=True)
        self.assertEqual(test_net['name'], 'test_net')
        test_subnet = self.create_subnet(
            test_net, client=self.os_admin.subnets_client,
            name='test_subnet', cidr='10.1.0.0/24')
        self.assertEqual(test_subnet['name'], 'test_subnet')
        self.assertEqual(test_subnet['cidr'], '10.1.0.0/24')
        _, model = self._run_container(nets=[{'network': test_net['id']}])
        self.assertEqual(1, len(model.addresses))
        subnet_id = list(model.addresses.values())[0][0]['subnet_id']
        addr = list(model.addresses.values())[0][0]['addr']
        self.assertEqual(subnet_id, test_subnet['id'])
        self.assertIn('10.1.0', addr)

    @decorators.idempotent_id('7a947d75-ab23-439a-bd94-f6e219f716a9')
    def test_run_container_with_cinder_volumes(self):
        """Tests the following:

        1. Create a volume in cinder.
        2. Run a container with the volume mounted into a path in file system.
        3. Execute a command in the container to write some data to the volume.
        4. Delete the container (the volume is untouched).
        5. Create a new container with the same volume mounted.
        6. Execute a command in the container to read data from the volume.
        7. Assert the data read from the volume is the same as the data
           written in before.
        """
        # create a volume in cinder
        volume = self.vol_client.create_volume(
            name=data_utils.rand_name(), size=1)['volume']
        volume_id = volume['id']

        # create a container with the volume
        container_path = '/data'
        container_file = '/data/testfile'
        _, model = self._run_container(mounts=[{
            'source': volume_id, 'destination': container_path}])
        volume = self.vol_client.show_volume(volume_id)['volume']
        self.assertEqual('in-use', volume['status'])
        # write data into the volume
        resp, _ = self.container_client.exec_container(
            model.uuid,
            command="/bin/sh -c 'echo hello > %s'" % container_file)
        self.assertEqual(200, resp.status)
        # delete the container
        resp, _ = self.container_client.delete_container(
            model.uuid, params={'stop': True})
        self.assertEqual(204, resp.status)
        self.container_client.ensure_container_deleted(model.uuid)
        volume = self.vol_client.show_volume(volume_id)['volume']
        self.assertEqual('available', volume['status'])

        # create another container with the same volume
        _, model = self._run_container(mounts=[{
            'source': volume_id, 'destination': container_path}])
        volume = self.vol_client.show_volume(volume_id)['volume']
        self.assertEqual('in-use', volume['status'])
        # read data from the volume
        resp, body = self.container_client.exec_container(
            model.uuid, command='cat %s' % container_file)
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in encodeutils.safe_decode(body))

    @decorators.idempotent_id('e49231b2-b095-40d3-9b54-33bb1b371cbe')
    @utils.requires_microversion('1.20')
    def test_run_container_with_cinder_volume_dynamic_created(self):
        """Tests the following:

        1. Run a container with a dynamic-created volume mounted into a path
           in file system.
        2. Assert a volume is created in cinder with an attachment to
           the container.
        3. Execute a command in the container to write some data to the volume.
        4. Execute a command in the container to read data from the volume.
        5. Assert the data read from the volume is the same as the data
           written in before.
        6. Delete the container.
        7. Assert the cinder volume is removed in cinder.
        """
        # create a container with the volume
        container_path = '/data'
        container_file = '/data/testfile'
        _, model = self._run_container(mounts=[{
            'size': 1, 'destination': container_path}])
        # assert a volume is created in cinder with 'in-use' status.
        volume_id = None
        volumes = self.vol_client.list_volumes(detail=True)['volumes']
        for volume in volumes:
            for attachment in volume['attachments']:
                if attachment['server_id'] == model.uuid:
                    volume_id = volume['id']
                    break
        self.assertIsNotNone(volume_id)
        volume = self.vol_client.show_volume(volume_id)['volume']
        self.assertEqual('in-use', volume['status'])
        # write data into the volume
        resp, _ = self.container_client.exec_container(
            model.uuid,
            command="/bin/sh -c 'echo hello > %s'" % container_file)
        self.assertEqual(200, resp.status)
        # read data from the volume
        resp, body = self.container_client.exec_container(
            model.uuid, command='cat %s' % container_file)
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in encodeutils.safe_decode(body))
        # delete the container and assert the volume is removed.
        self.container_client.delete_container(
            model.uuid, params={'stop': True})
        self.container_client.ensure_container_deleted(model.uuid)
        self.assertRaises(lib_exc.NotFound,
                          self.vol_client.show_volume,
                          volume_id)

    @decorators.idempotent_id('8a4395ff-3a91-4a35-bd71-5248afc6c465')
    @utils.requires_microversion('1.25')
    def test_run_container_with_injected_file(self):
        # create a container with the volume
        file_content = 'Random text'
        container_file = '/data/testfile'
        _, model = self._run_container(mounts=[{
            'type': 'bind',
            'source': utils.encode_file_data(file_content),
            'destination': container_file}])
        # read data from the injected file
        resp, body = self.container_client.exec_container(
            model.uuid, command='cat %s' % container_file)
        self.assertEqual(200, resp.status)
        self.assertTrue(file_content in encodeutils.safe_decode(body))

    @decorators.idempotent_id('c3f02fa0-fdfb-49fc-95e2-6e4dc982f9be')
    def test_commit_container(self):
        """Test container snapshot

        This test does the following:
        1. Create a container
        2. Create and write to a file inside the container
        3. Commit the container and upload the snapshot to Glance
        4. Create another container from the snapshot image
        5. Verify the pre-created file is there
        """
        # This command creates a file inside the container
        command = ["/bin/sh", "-c", "echo hello > testfile;sleep 1000000"]
        _, model = self._run_container(command=command)

        try:
            resp, _ = self.container_client.commit_container(
                model.uuid, params={'repository': 'myrepo'})
            self.assertEqual(202, resp.status)
            self._ensure_image_active('myrepo')

            # This command outputs the content of pre-created file
            command = ["/bin/sh", "-c", "cat testfile;sleep 1000000"]
            _, model = self._run_container(
                image="myrepo", image_driver="glance", command=command)
            resp, body = self.container_client.logs_container(model.uuid)
            self.assertEqual(200, resp.status)
            self.assertTrue('hello' in encodeutils.safe_decode(body))
        finally:
            try:
                response = self.images_client.list_images()
                for image in response['images']:
                    if (image['name'] == 'myrepo' and
                            image['container_format'] == 'docker'):
                        self.images_client.delete_image(image['id'])
            except Exception:
                pass

    def _ensure_image_active(self, image_name):
        def is_image_in_desired_state():
            response = self.images_client.list_images()
            for image in response['images']:
                if (image['name'] == image_name and
                        image['container_format'] == 'docker' and
                        image['status'] == 'active'):
                    return True

            return False

        utils.wait_for_condition(is_image_in_desired_state)

    @decorators.idempotent_id('3fa024ef-aba1-48fe-9682-0d6b7854faa3')
    def test_start_stop_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.stop_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Stopped')
        self.assertEqual('Stopped',
                         self._get_container_state(model))

        resp, _ = self.container_client.start_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')
        self.assertEqual('Running',
                         self._get_container_state(model))

    @decorators.idempotent_id('b5f39756-8898-4e0e-a48b-dda0a06b66b6')
    def test_pause_unpause_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.pause_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Paused')
        self.assertEqual('Paused',
                         self._get_container_state(model))

        resp, _ = self.container_client.unpause_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')
        self.assertEqual('Running',
                         self._get_container_state(model))

    @decorators.idempotent_id('6179a588-3d48-4372-9599-f228411d1449')
    def test_kill_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.kill_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Stopped')
        self.assertEqual('Stopped',
                         self._get_container_state(model))

    @decorators.idempotent_id('c2e54321-0a70-4331-ba62-9dcaa75ac250')
    def test_reboot_container(self):
        _, model = self._run_container()
        docker_base_url = self._get_docker_url(model)
        container = self.docker_client.get_container(model.uuid,
                                                     docker_base_url)
        pid = container.get('State').get('Pid')

        resp, _ = self.container_client.reboot_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.docker_client.ensure_container_pid_changed(model.uuid, pid,
                                                        docker_base_url)
        self.assertEqual('Running',
                         self._get_container_state(model))
        # assert pid is changed
        container = self.docker_client.get_container(model.uuid,
                                                     docker_base_url)
        self.assertNotEqual(pid, container.get('State').get('Pid'))

    @decorators.idempotent_id('8a591ff8-6793-427f-82a6-e3921d8b4f81')
    def test_exec_container(self):
        _, model = self._run_container()
        resp, body = self.container_client.exec_container(model.uuid,
                                                          command='echo hello')
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in encodeutils.safe_decode(body))

    @decorators.idempotent_id('a912ca23-14e7-442f-ab15-e05aaa315204')
    def test_logs_container(self):
        _, model = self._run_container(
            command=["/bin/sh", "-c", "echo hello;sleep 1000000"])
        resp, body = self.container_client.logs_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in encodeutils.safe_decode(body))

    @decorators.idempotent_id('d383f359-3ebd-40ef-9dc5-d36922790230')
    @utils.requires_microversion('1.14')
    def test_update_container(self):
        _, model = self._run_container(cpu=0.1, memory=100)
        self.assertEqual('100', model.memory)
        self.assertEqual(0.1, model.cpu)
        docker_base_url = self._get_docker_url(model)
        container = self.docker_client.get_container(model.uuid,
                                                     docker_base_url)
        self._assert_resource_constraints(container, cpu=0.1, memory=100)

        gen_model = datagen.container_patch_data(cpu=0.2, memory=200)
        resp, model = self.container_client.update_container(model.uuid,
                                                             gen_model)
        self.assertEqual(200, resp.status)
        self.assertEqual('200', model.memory)
        self.assertEqual(0.2, model.cpu)
        container = self.docker_client.get_container(model.uuid,
                                                     docker_base_url)
        self._assert_resource_constraints(container, cpu=0.2, memory=200)

    @decorators.idempotent_id('b218bea7-f19b-499f-9819-c7021ffc59f4')
    @utils.requires_microversion('1.14')
    def test_rename_container(self):
        container1_name = data_utils.rand_name('container1')
        _, model = self._run_container(name=container1_name)
        self.assertEqual(container1_name, model.name)
        container2_name = data_utils.rand_name('container2')
        gen_model = datagen.container_rename_data(name=container2_name)
        resp, model = self.container_client.update_container(model.uuid,
                                                             gen_model)
        self.assertEqual(200, resp.status)
        self.assertEqual(container2_name, model.name)

    @decorators.idempotent_id('142b7716-0b21-41ed-b47d-a42fba75636b')
    def test_top_container(self):
        _, model = self._run_container(
            command=["/bin/sh", "-c", "sleep 1000000"])
        resp, body = self.container_client.top_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertTrue('sleep 1000000' in encodeutils.safe_decode(body))

    @decorators.idempotent_id('09638306-b501-4803-aafa-7e8025632cef')
    def test_stats_container(self):
        _, model = self._run_container()
        resp, body = self.container_client.stats_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertTrue('NET I/O(B)' in encodeutils.safe_decode(body))
        self.assertTrue('CONTAINER' in encodeutils.safe_decode(body))
        self.assertTrue('MEM LIMIT(MiB)' in encodeutils.safe_decode(body))
        self.assertTrue('CPU %' in encodeutils.safe_decode(body))
        self.assertTrue('MEM USAGE(MiB)' in encodeutils.safe_decode(body))
        self.assertTrue('MEM %' in encodeutils.safe_decode(body))
        self.assertTrue('BLOCK I/O(B)' in encodeutils.safe_decode(body))

    def _assert_resource_constraints(self, container, cpu=None, memory=None):
        if cpu is not None:
            cpu_quota = container.get('HostConfig').get('CpuQuota')
            self.assertEqual(int(cpu * 100000), cpu_quota)
            cpu_period = container.get('HostConfig').get('CpuPeriod')
            self.assertEqual(100000, cpu_period)
        if memory is not None:
            docker_memory = container.get('HostConfig').get('Memory')
            self.assertEqual(memory * 1024 * 1024, docker_memory)

    def _create_container(self, **kwargs):
        gen_model = datagen.container_data(**kwargs)
        resp, model = self.container_client.post_container(gen_model)
        self.containers.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to finish creation
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Created')

        # Assert the container is created
        resp, model = self.container_client.get_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertEqual('Created', model.status)
        self.assertEqual('Created', self._get_container_state(model))
        return resp, model

    def _run_container(self, gen_model=None, **kwargs):
        if gen_model is None:
            gen_model = datagen.container_data(**kwargs)
        resp, model = self.container_client.run_container(gen_model)
        self.containers.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to started
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')

        # Assert the container is started
        resp, model = self.container_client.get_container(model.uuid)
        self.assertEqual('Running', model.status)
        self.assertEqual('Running', self._get_container_state(model))
        return resp, model

    def _get_container_state(self, model):
        container = self.docker_client.get_container(
            model.uuid, self._get_docker_url(model))
        status = container.get('State')
        if status.get('Error') is True:
            return 'Error'
        elif status.get('Paused'):
            return 'Paused'
        elif status.get('Running'):
            return 'Running'
        elif status.get('Status') == 'created':
            return 'Created'
        else:
            return 'Stopped'

    def _get_all_security_groups(self, container):
        # find all neutron ports of this container
        port_ids = set()
        for addrs_list in container.addresses.values():
            for addr in addrs_list:
                port_id = addr['port']
                port_ids.add(port_id)

        # find all security groups of this container
        sg_ids = set()
        for port_id in port_ids:
            port = self.ports_client.show_port(port_id)
            for sg in port['port']['security_groups']:
                sg_ids.add(sg)

        sg_names = []
        for sg_id in sg_ids:
            sg = self.sgs_client.show_security_group(sg_id)
            sg_names.append(sg['security_group']['name'])

        return sg_names

    def _get_docker_url(self, container=None, host='localhost'):
        protocol = 'tcp'
        port = '2375'
        if container:
            if not hasattr(container, 'host'):
                _, container = self.os_admin.container_client.get_container(
                    container.uuid, params={'all_projects': True})
            host = container.host
        # NOTE(kiennt): By default, devstack-plugin-container will
        #               set docker_api_url = {
        #                       "unix://$DOCKER_ENGINE_SOCKET_FILE",
        #                       "tcp://0.0.0.0:$DOCKER_ENGINE_PORT"
        #                   }
        base_url = '{}://{}:{}' . format(protocol, host, port)
        return base_url

    @decorators.idempotent_id('dcb0dddb-7f0f-43f6-b82a-0cae13938bd6')
    def test_detach_and_attach_network_to_container(self):
        _, model = self._run_container()

        self.assertEqual(1, len(model.addresses))
        network = list(model.addresses.keys())[0]
        resp, body = self.container_client.network_detach(
            model.uuid, params={'network': network})
        self._ensure_network_detached(model, network)
        resp, body = self.container_client.network_attach(
            model.uuid, params={'network': network})
        self._ensure_network_attached(model, network)

    @decorators.idempotent_id('037d800c-2262-4e15-90cd-95292b5ef958')
    @utils.requires_microversion('1.1', '1.24')
    def test_put_and_get_archive_from_container(self):
        _, model = self._run_container()
        self.assertEqual(1, len(model.addresses))

        # Create a simple tarstream
        file_content = 'Random text'

        tarstream = BytesIO()
        with tarfile.open(fileobj=tarstream, mode='w') as tar:
            encoded_file_content = file_content.encode()
            tarinfo = tarfile.TarInfo(name='test.txt')
            tarinfo.size = len(encoded_file_content)
            tarinfo.mtime = time.time()
            tar.addfile(tarinfo, BytesIO(encoded_file_content))

        # We're at the end of the tarstream, go back to the beginning
        tarstream.seek(0)

        req_body = json.dump_as_bytes({'data': tarstream.getvalue()})
        resp, _ = self.container_client.put_archive(
            model.uuid, params={'path': '/tmp'}, body=req_body)
        self.assertEqual(200, resp.status)
        resp, body = self.container_client.get_archive(
            model.uuid, params={'path': '/tmp/test.txt'})
        self.assertEqual(200, resp.status)

        # Get content
        body = json.loads(body)
        tardata = BytesIO(body['data'].encode())
        with tarfile.open(fileobj=tardata, mode='r') as tar:
            untar_content = tar.extractfile('test.txt').read()

        self.assertEqual(file_content, untar_content.decode())
        self.assertEqual(body['stat']['name'], tarinfo.name)
        self.assertEqual(body['stat']['size'], tarinfo.size)

    @decorators.idempotent_id('4ea3a2a5-cf89-48e7-bdd2-0bafc70ca7cb')
    @utils.requires_microversion('1.25')
    def test_put_and_get_archive_from_container_encoded(self):
        _, model = self._run_container()
        self.assertEqual(1, len(model.addresses))

        # Create a simple tarstream
        file_content = 'Random text'

        tarstream = BytesIO()
        with tarfile.open(fileobj=tarstream, mode='w') as tar:
            encoded_file_content = file_content.encode()
            tarinfo = tarfile.TarInfo(name='test.txt')
            tarinfo.size = len(encoded_file_content)
            tarinfo.mtime = time.time()
            tar.addfile(tarinfo, BytesIO(encoded_file_content))

        # We're at the end of the tarstream, go back to the beginning
        tarstream.seek(0)

        req_body = json.dump_as_bytes({
            'data': utils.encode_file_data(tarstream.getvalue())})
        resp, _ = self.container_client.put_archive(
            model.uuid, params={'path': '/tmp'}, body=req_body)
        self.assertEqual(200, resp.status)
        resp, body = self.container_client.get_archive(
            model.uuid, params={'path': '/tmp/test.txt'})
        self.assertEqual(200, resp.status)

        # Get content
        body = json.loads(body)
        tardata = BytesIO(utils.decode_file_data(body['data']))
        with tarfile.open(fileobj=tardata, mode='r') as tar:
            untar_content = tar.extractfile('test.txt').read()

        self.assertEqual(file_content, untar_content.decode())
        self.assertEqual(body['stat']['name'], tarinfo.name)
        self.assertEqual(body['stat']['size'], tarinfo.size)

    def _ensure_network_detached(self, container, network):
        def is_network_detached():
            _, model = self.container_client.get_container(container.uuid)
            if network not in model.addresses:
                return True
            else:
                return False

        utils.wait_for_condition(is_network_detached)

    def _ensure_network_attached(self, container, network):
        def is_network_attached():
            _, model = self.container_client.get_container(container.uuid)
            if network in model.addresses:
                return True
            else:
                return False

        utils.wait_for_condition(is_network_attached)


class TestContainerLegacy(TestContainer):

    credentials = ['primary', 'admin']
    min_microversion = '1.1'
    max_microversion = '1.19'

    def _run_container(self, gen_model=None, **kwargs):
        if 'command' in kwargs and isinstance(kwargs['command'], list):
            command = ' '.join(["'%s'" % c for c in kwargs['command']])
            kwargs['command'] = command
        if gen_model is None:
            gen_model = datagen.container_data_legacy(**kwargs)
        resp, model = self.container_client.run_container(gen_model)
        self.containers.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to started
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')

        # Assert the container is started
        resp, model = self.container_client.get_container(model.uuid)
        self.assertEqual('Running', model.status)
        self.assertEqual('Running', self._get_container_state(model))
        return resp, model

    def _create_container(self, **kwargs):
        if 'command' in kwargs and isinstance(kwargs['command'], list):
            command = ' '.join(["'%s'" % c for c in kwargs['command']])
            kwargs['command'] = command
        gen_model = datagen.container_data_legacy(**kwargs)
        resp, model = self.container_client.post_container(gen_model)
        self.containers.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to finish creation
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Created')

        # Assert the container is created
        resp, model = self.container_client.get_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertEqual('Created', model.status)
        self.assertEqual('Created', self._get_container_state(model))
        return resp, model
