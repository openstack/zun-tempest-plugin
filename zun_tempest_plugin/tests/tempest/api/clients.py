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
from six.moves.urllib import parse
from tempest.common import credentials_factory as common_creds
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib.common import rest_client
from tempest.lib.services.image.v2 import images_client
from tempest.lib.services.network import ports_client
from tempest.lib.services.network import security_groups_client
from tempest import manager

from zun_tempest_plugin.tests.tempest.api.models import container_model
from zun_tempest_plugin.tests.tempest.api.models import service_model
from zun_tempest_plugin.tests.tempest import utils


CONF = config.CONF

ADMIN_CREDS = None

CONTAINER_MANAGEMENT_MICROVERSION = None


def get_container_management_api_version():
    """Get zun-api-version with format: 'container X.Y'"""
    return 'container ' + CONTAINER_MANAGEMENT_MICROVERSION


def set_container_management_api_microversion(
        container_management_microversion):
    global CONTAINER_MANAGEMENT_MICROVERSION
    CONTAINER_MANAGEMENT_MICROVERSION = container_management_microversion


def reset_container_management_api_microversion():
    global CONTAINER_MANAGEMENT_MICROVERSION
    CONTAINER_MANAGEMENT_MICROVERSION = None


class Manager(manager.Manager):

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
        super(Manager, self).__init__(credentials=credentials)

        self.images_client = images_client.ImagesClient(
            self.auth_provider, 'image', CONF.identity.region)
        self.ports_client = ports_client.PortsClient(
            self.auth_provider, 'network', CONF.identity.region)
        self.sgs_client = security_groups_client.SecurityGroupsClient(
            self.auth_provider, 'network', CONF.identity.region)
        self.container_client = ZunClient(self.auth_provider)


class ZunClient(rest_client.RestClient):
    """"Base Tempest REST client for Zun API."""

    api_microversion_header_name = 'OpenStack-API-Version'

    def __init__(self, auth_provider):
        super(ZunClient, self).__init__(
            auth_provider=auth_provider,
            service=CONF.container_management.catalog_type,
            region=CONF.identity.region,
            disable_ssl_certificate_validation=True
        )

    def get_headers(self):
        headers = super(ZunClient, self).get_headers()
        if CONTAINER_MANAGEMENT_MICROVERSION:
            headers[self.api_microversion_header_name] = \
                get_container_management_api_version()
        return headers

    def request(self, *args, **kwargs):
        resp, resp_body = super(ZunClient, self).request(*args, **kwargs)
        if (CONTAINER_MANAGEMENT_MICROVERSION and
            CONTAINER_MANAGEMENT_MICROVERSION
                != api_version_utils.LATEST_MICROVERSION):
            api_version_utils.assert_version_header_matches_request(
                self.api_microversion_header_name,
                get_container_management_api_version(),
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

    def exec_container(self, container_id, command, **kwargs):
        return self.post(
            self.container_uri(container_id, action='execute'),
            '{"command": "%s"}' % command, **kwargs)

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

    def list_services(self, **kwargs):
        resp, body = self.get(self.services_uri(), **kwargs)
        return self.deserialize(resp, body,
                                service_model.ServiceCollection)

    def ensure_container_in_desired_state(self, container_id, status):
        def is_container_in_desired_state():
            _, container = self.get_container(container_id)
            if container.status == status:
                return True
            else:
                return False
        utils.wait_for_condition(is_container_in_desired_state, timeout=120)

    def ensure_container_deleted(self, container_id):
        def is_container_deleted():
            _, model = self.list_containers()
            container_ids = [c['uuid'] for c in model.containers]
            if container_id in container_ids:
                return False
            else:
                return True
        utils.wait_for_condition(is_container_deleted)

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

    def list_instances(self, inspect=False):
        """List all containers."""
        res = []
        for container in self.containers(all=True):
            info = self.inspect_container(container['Id'])
            if not info:
                continue
            if inspect:
                res.append(info)
            else:
                res.append(info['Config'].get('Hostname'))
        return res

    def list_containers(self):
        return self.containers(all=True, filters={'name': 'zun-'})


class DockerClient(object):

    def get_container(self, container_id,
                      docker_auth_url=CONF.docker.api_url):
        with docker_client(docker_auth_url) as docker:
            for info in docker.list_instances(inspect=True):
                if container_id in info['Name']:
                    return info
            return None

    def ensure_container_pid_changed(
            self, container_id, pid,
            docker_auth_url=CONF.docker.api_url):
        def is_pid_changed():
            container = self.get_container(container_id,
                                           docker_auth_url=docker_auth_url)
            new_pid = container.get('State').get('Pid')
            if pid != new_pid:
                return True
            else:
                return False
        utils.wait_for_condition(is_pid_changed)

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
