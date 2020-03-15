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

from zun_tempest_plugin.tests.tempest.api.common import base_model


class HostData(base_model.BaseModel):
    """Data that encapsulates host attributes"""
    pass


class HostEntity(base_model.EntityModel):
    """Entity Model that represents a single instance of HostData"""
    ENTITY_NAME = 'host'
    MODEL_TYPE = HostData


class HostCollection(base_model.CollectionModel):
    """Collection Model that represents a list of HostData objects"""
    COLLECTION_NAME = 'hosts'
    MODEL_TYPE = HostData
