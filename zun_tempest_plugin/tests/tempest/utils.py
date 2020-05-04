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

import base64
import functools
import time

from tempest import config
from tempest.lib.common import api_version_utils


CONF = config.CONF


def wait_for_condition(condition, interval=2, timeout=60):
    start_time = time.time()
    end_time = time.time() + timeout
    while time.time() < end_time:
        result = condition()
        if result:
            return result
        time.sleep(interval)
    raise Exception(("Timed out after %s seconds.  Started on %s and ended "
                     "on %s") % (timeout, start_time, end_time))


def requires_microversion(min_version, max_version='latest', **kwargs):
    """A decorator to skip tests if a microversion is not matched

    @param extension
    @param service
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *func_args, **func_kwargs):
            selected_version = api_version_utils.select_request_microversion(
                self.request_microversion,
                CONF.container_service.min_microversion)
            api_version_utils.check_skip_with_microversion(
                min_version,
                max_version,
                selected_version,
                selected_version)
            return func(self, *func_args, **func_kwargs)
        return wrapper
    return decorator


def encode_file_data(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')


def decode_file_data(data):
    return base64.b64decode(data)
