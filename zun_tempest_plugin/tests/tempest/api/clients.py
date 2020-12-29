# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import contextlib

import docker
from tempest import clients as tempest_clients
from tempest.common import credentials_factory as common_creds
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib.common import rest_client
from tempest.lib.services import clients
from tempest.lib.services.image.v2 import images_client
from tempest.lib.services.network import floating_ips_client
from tempest.lib.services.network import networks_client
from tempest.lib.services.network import ports_client
from tempest.lib.services.network import routers_client
from tempest.lib.services.network import security_group_rules_client
from tempest.lib.services.network import security_groups_client
from tempest.lib.services.network import subnetpools_client
from tempest.lib.services.network import subnets_client
from tempest.lib.services.volume.v3 import volumes_client
from urllib import parse

from zun_tempest_plugin.tests.tempest.api.models import capsule_model
from zun_tempest_plugin.tests.tempest.api.models import container_model
from zun_tempest_plugin.tests.tempest.api.models import host_model
from zun_tempest_plugin.tests.tempest.api.models import service_model
from zun_tempest_plugin.tests.tempest import utils


CONF = config.CONF

ADMIN_CREDS = None

CONTAINER_SERVICE_MICROVERSION = None


def get_container_service_api_version():
    """Get zun-api-version with format: 'container X.Y'"""
    return 'container ' + CONTAINER_SERVICE_MICROVERSION


def set_container_service_api_microversion(
        container_service_microversion):
    global CONTAINER_SERVICE_MICROVERSION
    CONTAINER_SERVICE_MICROVERSION = container_service_microversion


def reset_container_service_api_microversion():
    global CONTAINER_SERVICE_MICROVERSION
    CONTAINER_SERVICE_MICROVERSION = None


class Manager(clients.ServiceClients):

    def __init__(self, credentials=None):
        """Initialization of Manager class.

        Setup service client and make it available for test cases.
        :param credentials: type Credentials or TestResources
        """
        if credentials is None:
            global ADMIN_CREDS
            if ADMIN_CREDS is None:
                ADMIN_CREDS = common_creds.get_configured_admin_credentials()
            credentials = ADMIN_CREDS
        dscv = CONF.identity.disable_ssl_certificate_validation
        _, uri = tempest_clients.get_auth_provider_class(credentials)
        super(Manager, self).__init__(
            credentials=credentials,
            identity_uri=uri,
            scope='project',
            disable_ssl_certificate_validation=dscv,
            ca_certs=CONF.identity.ca_certificates_file,
            trace_requests=CONF.debug.trace_requests)

        self.images_client = images_client.ImagesClient(
            self.auth_provider, 'image', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.ports_client = ports_client.PortsClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.sgs_client = security_groups_client.SecurityGroupsClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.sg_rules_client = \
            security_group_rules_client.SecurityGroupRulesClient(
                self.auth_provider, 'network', CONF.identity.region,
                disable_ssl_certificate_validation=True)
        self.vol_client = volumes_client.VolumesClient(
            self.auth_provider, 'volumev3', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.container_client = ZunClient(self.auth_provider)
        self.neutron_client = networks_client.NetworksClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.subnets_client = subnets_client.SubnetsClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.subnetpools_client = subnetpools_client.SubnetpoolsClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.fip_client = floating_ips_client.FloatingIPsClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)
        self.routers_client = routers_client.RoutersClient(
            self.auth_provider, 'network', CONF.identity.region,
            disable_ssl_certificate_validation=True)


class ZunClient(rest_client.RestClient):
    """"Base Tempest REST client for Zun API."""

    api_microversion_header_name = 'OpenStack-API-Version'

    def __init__(self, auth_provider):
        super(ZunClient, self).__init__(
            auth_provider=auth_provider,
            service=CONF.container_service.catalog_type,
            region=CONF.identity.region,
            disable_ssl_certificate_validation=True
        )

    def get_headers(self):
        headers = super(ZunClient, self).get_headers()
        if CONTAINER_SERVICE_MICROVERSION:
            headers[self.api_microversion_header_name] = \
                get_container_service_api_version()
        return headers

    def request(self, *args, **kwargs):
        resp, resp_body = super(ZunClient, self).request(*args, **kwargs)
        if (CONTAINER_SERVICE_MICROVERSION and
            CONTAINER_SERVICE_MICROVERSION !=
                api_version_utils.LATEST_MICROVERSION):
            api_version_utils.assert_version_header_matches_request(
                self.api_microversion_header_name,
                get_container_service_api_version(),
                resp)
        return resp, resp_body

    @classmethod
    def deserialize(cls, resp, body, model_type):
        return resp, model_type.from_json(body)

    @classmethod
    def containers_uri(cls, params=None):
        url = "/containers/"
        if params:
            url = cls.add_params(url, params)
        return url

    @classmethod
    def container_uri(cls, container_id, action=None, params=None):
        """Construct container uri

        """
        url = None
        if action is None:
            url = "{0}/{1}".format(cls.containers_uri(), container_id)
        else:
            url = "{0}/{1}/{2}".format(cls.containers_uri(), container_id,
                                       action)

        if params:
            url = cls.add_params(url, params)

        return url

    def container_action_uri(cls, container_id, request_id):
        url = "/containers/{0}/container_actions/{1}".format(
            container_id, request_id)
        return url

    @classmethod
    def add_params(cls, url, params):
        """add_params adds dict values (params) to url as query parameters

        :param url: base URL for the request
        :param params: dict with var:val pairs to add as parameters to URL
        :returns: url string
        """
        url_parts = list(parse.urlparse(url))
        query = dict(parse.parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = parse.urlencode(query)
        return parse.urlunparse(url_parts)

    @classmethod
    def services_uri(cls):
        url = "/services/"
        return url

    @classmethod
    def capsules_uri(cls):
        url = "/capsules/"
        return url

    @classmethod
    def capsule_uri(cls, capsule_id, params=None):
        """Construct capsule uri

        """
        url = "{0}/{1}".format(cls.capsules_uri(), capsule_id)
        if params:
            url = cls.add_params(url, params)

        return url

    @classmethod
    def networks_uri(cls):
        url = "/networks/"
        return url

    @classmethod
    def network_uri(cls, network_id, params=None):
        url = "{0}/{1}".format(cls.networks_uri(), network_id)
        if params:
            url = cls.add_params(url, params)

        return url

    @classmethod
    def hosts_uri(cls):
        url = "/hosts/"
        return url

    def post_container(self, model, **kwargs):
        """Makes POST /container request

        """
        resp, body = self.post(
            self.containers_uri(),
            body=model.to_json(), **kwargs)
        return self.deserialize(resp, body, container_model.ContainerEntity)

    def run_container(self, model, **kwargs):
        resp, body = self.post(
            self.containers_uri(params={'run': True}),
            body=model.to_json(), **kwargs)
        return self.deserialize(resp, body, container_model.ContainerEntity)

    def get_container(self, container_id, params=None):
        resp, body = self.get(self.container_uri(container_id, params=params))
        return self.deserialize(resp, body, container_model.ContainerEntity)

    def list_containers(self, params=None, **kwargs):
        resp, body = self.get(self.containers_uri(params=params), **kwargs)
        return self.deserialize(resp, body,
                                container_model.ContainerCollection)

    def delete_container(self, container_id, params=None, **kwargs):
        return self.delete(
            self.container_uri(container_id, params=params), **kwargs)

    def commit_container(self, container_id, params=None, **kwargs):
        return self.post(
            self.container_uri(container_id, action='commit', params=params),
            None, **kwargs)

    def start_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='start'), None, **kwargs)

    def stop_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='stop'), None, *kwargs)

    def pause_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='pause'), None, **kwargs)

    def unpause_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='unpause'), None, **kwargs)

    def kill_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='kill'), None, **kwargs)

    def reboot_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='reboot'), None, **kwargs)

    def rebuild_container(self, container_id, **kwargs):
        return self.post(
            self.container_uri(container_id, action='rebuild'), None, **kwargs)

    def exec_container(self, container_id, command, **kwargs):
        resp, body = self.post(
            self.container_uri(container_id, action='execute'),
            '{"command": "%s"}' % command, **kwargs)
        return self.deserialize(
            resp, body, container_model.ContainerExecEntity)

    def logs_container(self, container_id, **kwargs):
        return self.get(
            self.container_uri(container_id, action='logs'), None, **kwargs)

    def update_container(self, container_id, model, **kwargs):
        resp, body = self.patch(
            self.container_uri(container_id), body=model.to_json(), **kwargs)
        return self.deserialize(resp, body, container_model.ContainerEntity)

    def rename_container(self, container_id, model, **kwargs):
        resp, body = self.post(
            self.container_uri(container_id, action='rename'),
            body=model.to_json(), **kwargs)
        return self.deserialize(resp, body, container_model.ContainerEntity)

    def top_container(self, container_id, **kwargs):
        return self.get(
            self.container_uri(container_id, action='top'), None, **kwargs)

    def stats_container(self, container_id, **kwargs):
        return self.get(
            self.container_uri(container_id, action='stats'), None, **kwargs)

    def add_security_group(self, container_id, model, **kwargs):
        return self.post(
            self.container_uri(container_id, action='add_security_group'),
            body=model.to_json(), **kwargs)

    def remove_security_group(self, container_id, model, **kwargs):
        return self.post(
            self.container_uri(container_id, action='remove_security_group'),
            body=model.to_json(), **kwargs)

    def list_services(self, **kwargs):
        resp, body = self.get(self.services_uri(), **kwargs)
        return self.deserialize(resp, body,
                                service_model.ServiceCollection)

    def get_container_action(self, container_id, request_id):
        resp, body = self.get(
            self.container_action_uri(container_id, request_id))
        return self.deserialize(
            resp, body, container_model.ContainerActionEntity)

    def ensure_container_in_desired_state(self, container_id, status):
        def is_container_in_desired_state():
            _, container = self.get_container(container_id)
            if container.status == status:
                return True
            else:
                return False
        utils.wait_for_condition(is_container_in_desired_state, timeout=240)

    def ensure_container_deleted(self, container_id):
        def is_container_deleted():
            _, model = self.list_containers()
            container_ids = [c['uuid'] for c in model.containers]
            if container_id in container_ids:
                return False
            else:
                return True
        utils.wait_for_condition(is_container_deleted, timeout=240)

    def ensure_action_finished(self, container_id, request_id):
        def is_action_finished():
            _, action = self.get_container_action(container_id, request_id)
            if action.finish_time is not None:
                return True
            else:
                return False
        utils.wait_for_condition(is_action_finished, timeout=120)

    def network_attach(self, container_id, params=None, **kwargs):
        return self.post(
            self.container_uri(container_id, action='network_attach',
                               params=params),
            None, **kwargs)

    def network_detach(self, container_id, params=None, **kwargs):
        return self.post(
            self.container_uri(container_id, action='network_detach',
                               params=params),
            None, **kwargs)

    def put_archive(self, container_id, params=None, **kwargs):
        return self.post(
            self.container_uri(container_id, action='put_archive',
                               params=params), **kwargs)

    def get_archive(self, container_id, params=None, **kwargs):
        return self.get(
            self.container_uri(container_id, action='get_archive',
                               params=params), None, **kwargs)

    def post_capsule(self, model, **kwargs):
        """Makes POST /capsules request

        """
        resp, body = self.post(
            self.capsules_uri(),
            body=model.to_json(), **kwargs)
        return self.deserialize(resp, body, capsule_model.CapsuleEntity)

    def ensure_capsule_in_desired_state(self, capsule_id, status):
        def is_capsule_in_desired_state():
            _, capsule = self.get_capsule(capsule_id)
            if capsule.status == status:
                return True
            else:
                return False
        utils.wait_for_condition(is_capsule_in_desired_state, timeout=240)

    def list_capsules(self, **kwargs):
        resp, body = self.get(self.capsules_uri(), **kwargs)
        return self.deserialize(resp, body, capsule_model.CapsuleEntity)

    def get_capsule(self, capsule_id, params=None):
        resp, body = self.get(self.capsule_uri(capsule_id, params=params))
        return self.deserialize(resp, body, capsule_model.CapsuleEntity)

    def delete_capsule(self, capsule_id, params=None):
        return self.delete(self.capsule_uri(capsule_id, params=params))

    def ensure_capsule_deleted(self, capsule_id):
        def is_capsule_deleted():
            _, model = self.list_capsules()
            capsule_ids = [c['uuid'] for c in model.capsules]
            if capsule_id in capsule_ids:
                return False
            else:
                return True
        utils.wait_for_condition(is_capsule_deleted, timeout=240)

    def delete_network(self, network_id, params=None):
        return self.delete(self.network_uri(network_id, params=params))

    def list_hosts(self, **kwargs):
        resp, body = self.get(self.hosts_uri(), **kwargs)
        return self.deserialize(resp, body,
                                host_model.HostCollection)


@contextlib.contextmanager
def docker_client(docker_auth_url):
    yield DockerHTTPClient(
        docker_auth_url,
        CONF.docker.docker_remote_api_version,
        CONF.docker.default_timeout
    )


class DockerHTTPClient(docker.APIClient):
    def __init__(self, url=CONF.docker.api_url,
                 ver=CONF.docker.docker_remote_api_version,
                 timeout=CONF.docker.default_timeout):
        super(DockerHTTPClient, self).__init__(
            base_url=url,
            version=ver,
            timeout=timeout,
            tls=False
        )


class DockerClient(object):

    def pull_image(
            self, repo, tag=None,
            docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            docker.pull(repo, tag=tag)

    def get_image(self, name, docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            return docker.get_image(name)

    def delete_image(self, name, docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            return docker.remove_image(name)

    def list_networks(self, name,
                      docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            return docker.networks(names=[name])

    def remove_network(self, name,
                       docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            return docker.remove_network(name)
