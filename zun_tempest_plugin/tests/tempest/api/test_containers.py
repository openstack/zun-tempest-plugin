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
import random
import subprocess
import tarfile
import testtools
import time
import types

from oslo_log import log as logging
from oslo_serialization import jsonutils as json
from oslo_utils import encodeutils
from tempest.common.utils import net_utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from zun_tempest_plugin.tests.tempest.api import clients
from zun_tempest_plugin.tests.tempest.api.common import datagen
from zun_tempest_plugin.tests.tempest import base
from zun_tempest_plugin.tests.tempest import utils


CONF = config.CONF
LOG = logging.getLogger(__name__)


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
        cls.sg_rules_client = cls.os_primary.sg_rules_client

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
        resp, _ = self.container_client.delete_container(container.uuid)
        self.assertEqual(204, resp.status)
        self.container_client.ensure_container_deleted(container.uuid)

    @decorators.idempotent_id('ef69c9e7-0ce0-4e14-b7ec-c1dc581a3927')
    def test_run_container(self):
        _, model = self._run_container(
            environment={'key1': 'env1', 'key2': 'env2'},
            labels={'key1': 'label1', 'key2': 'label2'},
            restart_policy={'Name': 'on-failure', 'MaximumRetryCount': 2},
        )
        resp, model = self.container_client.get_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertEqual({'key1': 'env1', 'key2': 'env2'}, model.environment)
        self.assertEqual({'key1': 'label1', 'key2': 'label2'}, model.labels)
        self.assertEqual({'Name': 'on-failure', 'MaximumRetryCount': '2'},
                         model.restart_policy)

    @decorators.idempotent_id('a2152d78-b6a6-4f47-8767-d83d29c6fb19')
    def test_run_container_with_minimal_params(self):
        gen_model = datagen.container_data({'image': 'nginx'})
        self._run_container(gen_model=gen_model)

    @decorators.idempotent_id('c32f93e3-da88-4c13-be38-25d2e662a28e')
    def test_run_container_with_image_driver_glance(self):
        if not CONF.service_available.glance:
            raise self.skipException("This test requires glance service")

        image_name = 'alpine'
        docker_base_url = self._get_docker_url()
        self.docker_client.pull_image(
            image_name, docker_auth_url=docker_base_url)
        image_data = self.docker_client.get_image(
            image_name, docker_base_url)
        if isinstance(image_data, types.GeneratorType):
            # NOTE(kiennt): In Docker-py 3.1.0, get_image
            #               returns generator [1]. These lines
            #               makes image_data readable.
            # [1] https://bugs.launchpad.net/zun/+bug/1753080
            image_data = ''.encode("latin-1").join(image_data)
            image_data = BytesIO(image_data)

        image = self.images_client.create_image(
            name=image_name, disk_format='raw', container_format='docker')
        self.addCleanup(self.images_client.delete_image, image['id'])
        self.images_client.store_image_file(image['id'], image_data)
        # delete the local image that was previously pulled down
        self.docker_client.delete_image(image_name, docker_base_url)

        _, model = self._run_container(
            image=image_name, image_driver='glance')

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

        port_name = data_utils.rand_name('port')
        port = self.create_port(tenant_network, name=port_name)
        port_address = port['fixed_ips'][0]['ip_address']
        port_subnet = port['fixed_ips'][0]['subnet_id']
        # NOTE(hongbin): port name will change in Rocky or earlier version
        # self.assertEqual(port_name, port['name'])
        self.assertEqual('', port['device_owner'])
        self.assertEqual('', port['device_id'])
        port = self.os_admin.ports_client.show_port(port['id'])['port']
        self.assertEqual('', port['binding:host_id'])
        self.assertEqual('unbound', port['binding:vif_type'])

        _, model = self._run_container(nets=[{'port': port['id']}])
        address = {'port': port['id'],
                   'addr': port_address,
                   'subnet_id': port_subnet}
        self._assert_container_has_address(model, address,
                                           network_id=tenant_network['id'])
        port = self.os_admin.ports_client.show_port(port['id'])['port']
        # NOTE(hongbin): port name will change in Rocky or earlier version
        # self.assertEqual(port_name, port['name'])
        self.assertTrue(port['device_owner'])
        self.assertEqual(model.uuid, port['device_id'])
        self.assertTrue(port['binding:host_id'])
        self.assertNotEqual('unbound', port['binding:vif_type'])

        resp, _ = self.container_client.delete_container(
            model.uuid, params={'stop': True})
        self.assertEqual(204, resp.status)
        self.container_client.ensure_container_deleted(model.uuid)
        port = self.os_admin.ports_client.show_port(port['id'])['port']
        # NOTE(hongbin): port name will change in Rocky or earlier version
        # self.assertEqual(port_name, port['name'])
        self.assertEqual('', port['device_owner'])
        self.assertEqual('', port['device_id'])
        self.assertEqual('', port['binding:host_id'])
        self.assertEqual('unbound', port['binding:vif_type'])

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
            if address.items() <= addr.items():
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

    @decorators.idempotent_id('f181eeda-a9d1-4b2e-9746-d6634ca81e2f')
    @utils.requires_microversion('1.20')
    def test_run_container_without_security_groups(self):
        gen_model = datagen.container_data()
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

    @decorators.idempotent_id('956e9944-3647-4f87-bdbf-017569549227')
    def test_run_container_with_no_gateway_subnet(self):
        test_net = self.create_network()
        test_subnet = self.create_subnet(
            test_net, cidr='10.1.0.0/24', gateway_ip=None)
        self.assertIsNone(test_subnet['gateway_ip'])
        _, model = self._run_container(nets=[{'network': test_net['id']}])
        self.assertEqual(1, len(model.addresses))
        subnet_id = list(model.addresses.values())[0][0]['subnet_id']
        addr = list(model.addresses.values())[0][0]['addr']
        self.assertEqual(subnet_id, test_subnet['id'])
        self.assertIn('10.1.0', addr)

    @decorators.idempotent_id('7a947d75-ab23-439a-bd94-f6e219f716a9')
    @testtools.skip('bug 1897497')
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
        self.assertTrue('hello' in body.output)

    @decorators.idempotent_id('df7b2518-f779-43f6-b188-28cf3595e251')
    @utils.requires_microversion('1.24')
    def test_container_expose_port(self):
        gen_model = datagen.container_data({'image': 'nginx',
                                            'exposed_ports': {"80/tcp": {}}})
        _, model = self._run_container(gen_model=gen_model)
        # assert security group is created with port 80 open
        secgroups = model.security_groups
        self.assertEqual(1, len(secgroups))
        secgroup = self.sgs_client.show_security_group(secgroups[0])
        self.assertNotEqual('default', secgroup['security_group']['name'])
        rules = secgroup['security_group']['security_group_rules']
        for rule in rules:
            if (rule['protocol'] == 'tcp' and rule['port_range_min'] == 80 and
                    rule['port_range_max'] == 80):
                break
        else:
            self.fail('Security group doesnot have rules for opening the port')

        # access the container port
        ip_address = None
        for net_id in model.addresses:
            for address in model.addresses[net_id]:
                ip_address = address['addr']
                break
        self.assertIsNotNone(ip_address)
        _, m = self._run_container(desired_state='Stopped',
                                   command=['curl', ip_address])
        time.sleep(1)  # wait for logs to print out
        resp, body = self.container_client.logs_container(m.uuid)
        self.assertEqual(200, resp.status)
        self.assertTrue(
            'If you see this page, the nginx web server is successfully '
            'installed' in encodeutils.safe_decode(body))

        # delete the container and ensure security group is clean up
        self.container_client.delete_container(
            model.uuid, params={'stop': True})
        self.container_client.ensure_container_deleted(model.uuid)
        self.assertRaises(lib_exc.NotFound,
                          self.sgs_client.show_security_group,
                          secgroup['security_group']['id'])

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
        self.assertTrue('hello' in body.output)
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
        self.assertTrue(file_content in body.output)

    @decorators.idempotent_id('0c8afb23-312d-4647-897d-b3c8591b26eb')
    @utils.requires_microversion('1.39')
    def test_run_container_with_requested_host(self):
        _, model = self.os_admin.container_client.list_hosts()
        hosts = model.hosts
        self.assertTrue(len(hosts) > 0)

        # create a container with the requested host
        requested_host = random.choice(hosts).hostname
        _, model = self._run_container(
            container_client=self.os_admin.container_client,
            host=requested_host)
        self.assertEqual(requested_host, model.host)

    @decorators.idempotent_id('c3f02fa0-fdfb-49fc-95e2-6e4dc982f9be')
    @utils.requires_microversion('1.1', '1.39')
    def test_commit_container(self):
        """Test container snapshot

        This test does the following:
        1. Create a container
        2. Create and write to a file inside the container
        3. Commit the container and upload the snapshot to Glance
        4. Create another container from the snapshot image
        5. Verify the pre-created file is there
        """
        if not CONF.service_available.glance:
            raise self.skipException("This test requires glance service")

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

    @decorators.idempotent_id('985c9060-b925-47d0-9ceb-10c547ce58a5')
    @utils.requires_microversion('1.40')
    def test_commit_container_140(self):
        """Test container snapshot

        This test does the following:
        1. Create a container
        2. Create and write to a file inside the container
        3. Commit the container and upload the snapshot to Glance
        4. Create another container from the snapshot image
        5. Verify the pre-created file is there
        """
        if not CONF.service_available.glance:
            raise self.skipException("This test requires glance service")

        # This command creates a file inside the container
        entrypoint = ["/bin/sh", "-c"]
        command = ["echo hello > testfile;sleep 1000000"]
        _, model = self._run_container(command=command, entrypoint=entrypoint)

        try:
            resp, _ = self.container_client.commit_container(
                model.uuid, params={'repository': 'myrepo'})
            self.assertEqual(202, resp.status)
            self._ensure_image_active('myrepo')

            # This command outputs the content of pre-created file
            entrypoint = ["/bin/sh", "-c"]
            command = ["cat testfile;sleep 1000000"]
            _, model = self._run_container(
                image="myrepo", image_driver="glance", command=command,
                entrypoint=entrypoint)
            time.sleep(1)  # wait for logs to print out
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

        resp, _ = self.container_client.start_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')

    @decorators.idempotent_id('b5f39756-8898-4e0e-a48b-dda0a06b66b6')
    def test_pause_unpause_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.pause_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Paused')

        resp, _ = self.container_client.unpause_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')

    @decorators.idempotent_id('6179a588-3d48-4372-9599-f228411d1449')
    def test_kill_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.kill_container(model.uuid)
        self.assertEqual(202, resp.status)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Stopped')

    @decorators.idempotent_id('c2e54321-0a70-4331-ba62-9dcaa75ac250')
    @testtools.skip('temporarily disabled')
    def test_reboot_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.reboot_container(model.uuid)
        self.assertEqual(202, resp.status)
        # TODO(hongbin): wait for reboot to complete and assure it succeeds

    @decorators.idempotent_id('a0c8843f-c32e-4658-b228-eb16c746f495')
    @utils.requires_microversion('1.33')
    def test_rebuild_container(self):
        _, model = self._run_container()

        resp, _ = self.container_client.rebuild_container(model.uuid)
        self.assertEqual(202, resp.status)
        request_id = self._get_request_id(resp)
        # Wait for container to rebuild
        self.container_client.ensure_action_finished(
            model.uuid, request_id)

        resp, action = self.container_client.get_container_action(
            model.uuid, request_id)
        self.assertEqual(200, resp.status)
        # if the action succeeds, action.message will be None
        self.assertIsNone(action.message)
        self.container_client.ensure_container_in_desired_state(
            model.uuid, 'Running')

    @decorators.idempotent_id('8a591ff8-6793-427f-82a6-e3921d8b4f81')
    def test_exec_container(self):
        _, model = self._run_container()
        resp, body = self.container_client.exec_container(model.uuid,
                                                          command='echo hello')
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in body.output)

    @decorators.idempotent_id('a912ca23-14e7-442f-ab15-e05aaa315204')
    def test_logs_container(self):
        _, model = self._run_container(
            command=["/bin/sh", "-c", "echo hello;sleep 1000000"])
        time.sleep(1)  # wait for logs to print out
        resp, body = self.container_client.logs_container(model.uuid)
        self.assertEqual(200, resp.status)
        self.assertTrue('hello' in encodeutils.safe_decode(body))

    @decorators.idempotent_id('d383f359-3ebd-40ef-9dc5-d36922790230')
    @utils.requires_microversion('1.14')
    def test_update_container(self):
        _, model = self._run_container(cpu=0.1, memory=100)
        self.assertEqual('100', model.memory)
        self.assertEqual(0.1, model.cpu)

        gen_model = datagen.container_patch_data(cpu=0.2, memory=200)
        resp, model = self.container_client.update_container(model.uuid,
                                                             gen_model)
        self.assertEqual(200, resp.status)
        self.assertEqual('200', model.memory)
        self.assertEqual(0.2, model.cpu)

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
        return resp, model

    def _run_container(self, gen_model=None, desired_state='Running',
                       container_client=None, **kwargs):
        if gen_model is None:
            gen_model = datagen.container_data(**kwargs)
        if container_client is None:
            container_client = self.container_client
        resp, model = container_client.run_container(gen_model)
        self.containers.append(model.uuid)
        self.assertEqual(202, resp.status)
        # Wait for container to started
        container_client.ensure_container_in_desired_state(
            model.uuid, desired_state)

        # Assert the container is started
        resp, model = container_client.get_container(model.uuid)
        self.assertEqual(desired_state, model.status)
        return resp, model

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

    def _get_docker_url(self, host='localhost'):
        protocol = 'tcp'
        port = '2375'
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

    @decorators.idempotent_id('91d8bf98-9dbf-4c38-91c3-6dc8cc47132f')
    def test_container_network(self):
        """Basic network operation test

        For a freshly-booted container with an IP address ("port") on a given
        network:
        - the Tempest host can ping the IP address.  This implies, but
            does not guarantee, that the
            container has been assigned the correct IP address and has
            connectivity to the Tempest host.
        - the Tempest host can enter the container and
            successfully execute the following:
            - ping an external IP address, implying external connectivity.
            - ping an internal IP address, implying connectivity to another
               container on the same network.
        - detach the floating-ip from the container and verify that it becomes
            unreachable
        - associate detached floating ip to a new container and verify
            connectivity.
        Verifies that floating IP status is updated correctly after each change
        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            raise self.skipException(msg)

        container, floating_ip, network = self._setup_network_and_containers()
        self._check_public_network_connectivity(floating_ip,
                                                should_connect=True)
        self._check_network_internal_connectivity(container, network)
        self._check_network_external_connectivity(container)
        self._disassociate_floating_ips(floating_ip)
        self._check_public_network_connectivity(
            floating_ip, should_connect=False,
            msg="after disassociate floating ip")
        self._reassociate_floating_ips(floating_ip, network)
        self._check_public_network_connectivity(
            floating_ip, should_connect=True,
            msg="after re-associate floating ip")

    def _setup_network_and_containers(self, **kwargs):
        network = self.create_network()
        router = self.create_router()
        subnet = self.create_subnet(network, allocate_cidr=True)
        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], subnet_id=subnet['id'])

        tenant_network_id = network['id']
        security_group = self._create_security_group()
        _, model = self._run_container(
            nets=[{'network': tenant_network_id}],
            security_groups=[security_group['name']])
        self.assertEqual(1, len(model.addresses))
        self.assertEqual(1, len(model.addresses[tenant_network_id]))
        port_id = model.addresses[tenant_network_id][0]['port']
        fixed_ip_address = model.addresses[tenant_network_id][0]['addr']

        floating_ip = self.fip_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=port_id,
            fixed_ip_address=fixed_ip_address)['floatingip']
        return model, floating_ip, network

    def _create_security_group(self):
        # Create security group
        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        secgroup = self.sgs_client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            self.sgs_client.delete_security_group,
            secgroup['id'])

        # Add rules to the security group
        self._create_pingable_secgroup_rule(secgroup)

        return secgroup

    def _create_pingable_secgroup_rule(self, secgroup, sg_rules_client=None):
        if sg_rules_client is None:
            sg_rules_client = self.sg_rules_client
        rulesets = [
            dict(
                # ping
                protocol='icmp',
            ),
            dict(
                # ipv6-icmp for ping6
                protocol='icmp',
                ethertype='IPv6',
            )
        ]
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    sg_rules_client.create_security_group_rule(
                        security_group_id=secgroup['id'],
                        project_id=secgroup['project_id'],
                        **ruleset)
                except lib_exc.Conflict as ex:
                    # if rule already exist - skip rule and continue
                    msg = 'Security group rule already exists'
                    if msg not in ex._error_string:
                        raise ex

    def _disassociate_floating_ips(self, floating_ip):
        floating_ip = self.fip_client.update_floatingip(
            floating_ip['id'], port_id=None)['floatingip']
        self.assertIsNone(floating_ip['port_id'])

    def _reassociate_floating_ips(self, floating_ip, network):
        # create a new container for the floating ip
        tenant_network_id = network['id']
        security_group = self._create_security_group()
        _, container = self._run_container(
            nets=[{'network': tenant_network_id}],
            security_groups=[security_group['name']])
        self.assertEqual(1, len(container.addresses))
        self.assertEqual(1, len(container.addresses[tenant_network_id]))
        port_id = container.addresses[tenant_network_id][0]['port']
        floating_ip = self.fip_client.update_floatingip(
            floating_ip['id'], port_id=port_id)['floatingip']
        self.assertEqual(port_id, floating_ip['port_id'])

    def _check_public_network_connectivity(
            self, floating_ip, should_connect=True, msg=None,
            should_check_floating_ip_status=True, mtu=None):
        ip_address = floating_ip['floating_ip_address']
        floatingip_status = 'DOWN'
        if should_connect:
            floatingip_status = 'ACTIVE'

        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            self._check_floating_ip_status(floating_ip, floatingip_status)

        message = 'Public network connectivity check failed'
        if msg:
            message += '. Reason: %s' % msg

        self._check_ip_connectivity(ip_address, should_connect, message,
                                    mtu=mtu)

    def _check_ip_connectivity(self, ip_address, should_connect=True,
                               extra_msg="", mtu=None):
        LOG.debug('checking network connections to IP: %s', ip_address)
        if should_connect:
            msg = "Timed out waiting for %s to become reachable" % ip_address
        else:
            msg = "ip address %s is reachable" % ip_address
        if extra_msg:
            msg = "%s\n%s" % (extra_msg, msg)
        self.assertTrue(self._ping_ip_address(ip_address,
                                              should_succeed=should_connect,
                                              mtu=mtu),
                        msg=msg)

    def _check_network_internal_connectivity(self, container, network,
                                             should_connect=True):
        """check container internal connectivity:

        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        # get internal ports' ips:
        # get all network and compute ports in the new network
        internal_ips = (
            p['fixed_ips'][0]['ip_address'] for p in
            self.os_admin.ports_client.list_ports(
                project_id=container.project_id,
                network_id=network['id'])['ports']
            if p['device_owner'].startswith('network')
        )

        for internal_ip in internal_ips:
            self._check_remote_connectivity(container, internal_ip,
                                            should_connect)

    def _check_network_external_connectivity(self, container):
        # We ping the external IP from the container using its floating IP
        # which is always IPv4, so we must only test connectivity to
        # external IPv4 IPs if the external network is dualstack.
        v4_subnets = [
            s for s in self.os_admin.subnets_client.list_subnets(
                network_id=CONF.network.public_network_id)['subnets']
            if s['ip_version'] == 4
        ]

        if len(v4_subnets) > 1:
            self.assertTrue(
                CONF.network.subnet_id,
                "Found %d subnets. Specify subnet using configuration "
                "option [network].subnet_id."
                % len(v4_subnets))
            subnet = self.os_admin.subnets_client.show_subnet(
                CONF.network.subnet_id)['subnet']
            external_ip = subnet['gateway_ip']
        else:
            external_ip = v4_subnets[0]['gateway_ip']

        self._check_remote_connectivity(container, external_ip)

    def _check_remote_connectivity(self, container, dest, should_succeed=True):
        def connect_remote():
            resp, body = self.container_client.exec_container(
                container.uuid,
                command="ping -c1 -w1 %s" % dest)
            self.assertEqual(200, resp.status)
            return (body.exit_code == 0) == should_succeed

        result = test_utils.call_until_true(connect_remote,
                                            CONF.validation.ping_timeout, 1)
        if result:
            return

        if should_succeed:
            msg = "Timed out waiting for %s to become reachable" % (
                dest)
        else:
            msg = "%s is reachable from container" % (dest)
        self.fail(msg)

    def _ping_ip_address(self, ip_address, should_succeed=True,
                         ping_timeout=None, mtu=None, server=None):
        timeout = ping_timeout or CONF.validation.ping_timeout
        cmd = ['ping', '-c1', '-w1']

        if mtu:
            cmd += [
                # don't fragment
                '-M', 'do',
                # ping receives just the size of ICMP payload
                '-s', str(net_utils.get_ping_payload_size(mtu, 4))
            ]
        cmd.append(ip_address)

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()

            return (proc.returncode == 0) == should_succeed

        caller = test_utils.find_test_caller()
        LOG.debug('%(caller)s begins to ping %(ip)s in %(timeout)s sec and the'
                  ' expected result is %(should_succeed)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'should_succeed':
                      'reachable' if should_succeed else 'unreachable'
                  })
        result = test_utils.call_until_true(ping, timeout, 1)
        LOG.debug('%(caller)s finishes ping %(ip)s in %(timeout)s sec and the '
                  'ping result is %(result)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'result': 'expected' if result else 'unexpected'
                  })
        return result

    def _check_floating_ip_status(self, floating_ip, status):
        floatingip_id = floating_ip['id']

        def refresh():
            floating_ip = (self.fip_client.
                           show_floatingip(floatingip_id)['floatingip'])
            if status == floating_ip['status']:
                LOG.info("FloatingIP: {fp} is at status: {st}"
                         .format(fp=floating_ip, st=status))
            return status == floating_ip['status']

        if not test_utils.call_until_true(refresh,
                                          CONF.network.build_timeout,
                                          CONF.network.build_interval):
            floating_ip = self.fip_client.show_floatingip(
                floatingip_id)['floatingip']
            self.assertEqual(status, floating_ip['status'],
                             message="FloatingIP: {fp} is at status: {cst}. "
                                     "failed  to reach status: {st}"
                             .format(fp=floating_ip, cst=floating_ip['status'],
                                     st=status))

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
        return resp, model
