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

import netaddr

from oslo_log import log as logging
from tempest import config
from tempest.lib.common import api_version_request
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from zun_tempest_plugin.tests.tempest.api import api_microversion_fixture
from zun_tempest_plugin.tests.tempest.api import clients


CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseZunTest(api_version_utils.BaseMicroversionTest,
                  test.BaseTestCase):

    credentials = ['primary']

    @classmethod
    def skip_checks(cls):
        super(BaseZunTest, cls).skip_checks()
        if not CONF.service_available.zun:
            skip_msg = 'Zun is disabled'
            raise cls.skipException(skip_msg)
        cfg_min_version = CONF.container_service.min_microversion
        cfg_max_version = CONF.container_service.max_microversion
        api_version_utils.check_skip_with_microversion(cls.min_microversion,
                                                       cls.max_microversion,
                                                       cfg_min_version,
                                                       cfg_max_version)

    @classmethod
    def setup_clients(cls):
        super(BaseZunTest, cls).setup_clients()
        cls.networks_client = cls.os_primary.neutron_client
        cls.subnets_client = cls.os_primary.subnets_client
        cls.docker_client = clients.DockerClient()
        cls.container_client = cls.os_primary.container_client
        cls.ports_client = cls.os_primary.ports_client
        cls.subnetpools_client = cls.os_primary.subnetpools_client
        cls.vol_client = cls.os_primary.vol_client
        cls.routers_client = cls.os_primary.routers_client
        cls.fip_client = cls.os_primary.fip_client

    @classmethod
    def setup_credentials(cls):
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.container_service.min_microversion
            ))
        cls.services_microversion = {
            CONF.container_service.catalog_type: cls.request_microversion}
        super(BaseZunTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(BaseZunTest, cls).resource_setup()
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.container_service.min_microversion))
        cls.wait_timeout = CONF.container_service.wait_timeout

    @classmethod
    def clear_credentials(cls):
        try:
            clients.set_container_service_api_microversion(
                cls.request_microversion)
            cls.cleanup_network()
        except lib_exc.NotFound:
            LOG.exception("Error on network cleanup.")
        finally:
            clients.reset_container_service_api_microversion()
        super(BaseZunTest, cls).clear_credentials()

    @classmethod
    def cleanup_network(cls):
        creds_provider = cls._get_credentials_provider()
        creds = creds_provider.get_primary_creds()
        network = getattr(creds, 'network', None)
        if not network:
            return

        req_version = api_version_request.APIVersionRequest(
            cls.request_microversion)
        if req_version >= api_version_request.APIVersionRequest('1.27'):
            cls.os_admin.container_client.delete_network(network['id'])
        else:
            # TODO(hongbin): remove such legacy cleanup logic after all
            # branches support 'delete_network' above.
            docker_url = 'tcp://localhost:2375'
            networks = cls.docker_client.list_networks(
                network['id'], docker_auth_url=docker_url)
            for network in networks:
                cls.docker_client.remove_network(
                    network['Id'], docker_auth_url=docker_url)

    def setUp(self):
        super(BaseZunTest, self).setUp()
        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            self.request_microversion
        ))

    def create_router(self, client=None, **values):
        client = client or self.routers_client
        kwargs = {
            'name': data_utils.rand_name('test-router'),
            'admin_state_up': True,
            'project_id': getattr(client, 'project_id', client.tenant_id),
            'external_gateway_info': {
                'network_id': CONF.network.public_network_id
            }
        }
        if values:
            kwargs.update(values)
        router = client.create_router(**kwargs)['router']
        self.addCleanup(client.delete_router, router['id'])
        return router

    def create_network(self, client=None, **values):
        kwargs = {'name': data_utils.rand_name('test-network')}
        if values:
            kwargs.update(values)
        client = client or self.networks_client
        network = client.create_network(**kwargs)['network']
        self.addCleanup(client.delete_network, network['id'])
        return network

    def create_subnet(self, network, client=None, allocate_cidr=False,
                      **values):
        kwargs = {'name': data_utils.rand_name('test-subnet'),
                  'network_id': network['id'],
                  'project_id': network['project_id'],
                  'ip_version': 4}
        if values:
            kwargs.update(values)
        client = client or self.subnets_client

        def cidr_in_use(cidr, project_id):
            """Check cidr existence

            :returns: True if subnet with cidr already exist in tenant
                  False else
            """
            cidr_in_use = self.os_admin.subnets_client.list_subnets(
                project_id=project_id, cidr=cidr)['subnets']
            return len(cidr_in_use) != 0

        if allocate_cidr:
            tenant_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
            num_bits = CONF.network.project_network_mask_bits

            subnet = None
            str_cidr = None
            # Repeatedly attempt subnet creation with sequential cidr
            # blocks until an unallocated block is found.
            for subnet_cidr in tenant_cidr.subnet(num_bits):
                str_cidr = str(subnet_cidr)
                if cidr_in_use(str_cidr, project_id=network['project_id']):
                    continue

                kwargs['cidr'] = str_cidr
                try:
                    subnet = client.create_subnet(**kwargs)['subnet']
                    self.addCleanup(client.delete_subnet, subnet['id'])
                    break
                except lib_exc.Conflict as e:
                    is_overlapping_cidr = \
                        'overlaps with another subnet' in str(e)
                    if not is_overlapping_cidr:
                        raise

            self.assertIsNotNone(subnet, 'Unable to allocate tenant network')
            self.assertEqual(subnet['cidr'], str_cidr)
            return subnet
        else:
            subnet = client.create_subnet(**kwargs)['subnet']
            self.addCleanup(client.delete_subnet, subnet['id'])
            return subnet

    def create_port(self, network, client=None, **values):
        kwargs = {'name': data_utils.rand_name('test-port'),
                  'network_id': network['id']}
        if values:
            kwargs.update(values)
        client = client or self.ports_client
        port = client.create_port(**kwargs)['port']
        self.addCleanup(client.delete_port, port['id'])
        return port

    def create_subnetpool(self, client=None, **values):
        kwargs = {'name': data_utils.rand_name('test-subnetpool')}
        if values:
            kwargs.update(values)
        client = client or self.subnetpools_client
        subnetpool = client.create_subnetpool(**kwargs)['subnetpool']
        self.addCleanup(client.delete_subnetpool, subnetpool['id'])
        return subnetpool

    def _get_request_id(self, resp):
        return resp.get('x-openstack-request-id', '')

    def _microversion_atleast(self, version):
        req_version = api_version_request.APIVersionRequest(
            self.request_microversion)
        return req_version >= api_version_request.APIVersionRequest(version)
