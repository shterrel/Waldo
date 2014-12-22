#   Copyright 2014 Rackspace
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

"""Waldo Python client."""

from __future__ import print_function

import copy
import getpass
import logging
import json
import sys
import os

import arrow
import requests

from waldoc import consts

LOG = logging.getLogger(__name__)


def log_messages_to_stdout():
    LOG.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    LOG.addHandler(ch)


def read_file(path):
    if os.path.exists(path):
        try:
            with open(path, 'r') as session_file:
                return session_file.read()
        except IOError:
            LOG.debug("Error reading from %s", path)


def waldo_token_cache():
    contents = read_file(consts.WALDO_SESSION_FILE)
    if contents is not None:
        contents = json.loads(contents)
        fields = ['user', 'token', 'expires']
        if sorted(contents.keys()) != sorted(fields):
            LOG.debug("Unexpected field in Waldo session file.")
            return
        if all([key in contents for key in fields]):
            timestamp = arrow.get(contents['expires'])
            if timestamp > arrow.now('UTC'):
                LOG.debug("Using token from Waldo session file")
                return contents['token']
            else:
                LOG.debug("Token from Waldo session file is expired.")
        else:
            LOG.debug("Waldo session file %s is missing one or more "
                      "required fields", consts.WALDO_SESSION_FILE)

    LOG.debug("No cached token found from Waldo client")


class Waldo(object):

    def __init__(self, username=None, endpoint=None, token=None,
                 auth_endpoint=None, password=None, rsa_token=False,
                 password_from_user=False):
        self.username = username or os.environ.get('WALDOCLIENT_USERNAME')
        self.endpoint = endpoint or consts.PRODUCTION
        self.auth_endpoint = auth_endpoint or consts.INTERNAL_AUTH
        self.password = password or os.environ.get('WALDOCLIENT_PASSWORD')
        self.rsa_token = rsa_token
        self.interactive = password_from_user
        self.token = token or self._get_token()

    def _get_token(self):
        """Fetch a Racker token from cache or from auth servers."""
        cached_token = waldo_token_cache()
        if cached_token is not None:
            return cached_token

        if not any([self.password, self.rsa_token, self.interactive]):
            raise AttributeError("Waldo client has not been provided enough "
                                 "information to attempt to authenticate.")

        if self.interactive and not any([self.password, self.rsa_token]):
            if not self.username:
                raise AttributeError("Username required. You may set it "
                                     "with `keyring set waldoclient username`")
            self.password = getpass.getpass("[%s] Password:" % self.username)

        (token, expires) = self.authenticate_racker(self.password,
                                                    self.rsa_token)

        # Cache newly acquired token
        cache_contents = json.dumps(
            {
                'user': self.username,
                'token': token,
                'expires': str(expires),
            }
        )
        with open(consts.WALDO_SESSION_FILE, 'w') as cache_file:
            cache_file.write(cache_contents)

        return token

    def authenticate_racker(self, password=None, rsa_key=None):
        """Autheticate a Racker using SSO credentials.

        :returns: authentication response.
        """
        if "/v2.0" not in self.auth_endpoint:
            self.auth_endpoint = self.auth_endpoint + "/v2.0"
        if "/tokens" not in self.auth_endpoint:
            self.auth_endpoint = self.auth_endpoint + "/tokens"
        headers = {'Content-Type': 'application/json'}

        if not self.username:
            raise AttributeError("No username supplied.")

        if rsa_key:
            payload = {
                "auth": {
                    "RAX-AUTH:domain": {
                        "name": "Rackspace"
                    },
                    "RAX-AUTH:rsaCredentials": {
                        "username": self.username,
                        "tokenKey": rsa_key
                    }
                }
            }
        elif password:
            payload = {
                "auth": {
                    "RAX-AUTH:domain": {
                        "name": "Rackspace"
                    },
                    "passwordCredentials": {
                        "username": self.username,
                        "password": password
                    }
                }
            }
        else:
            raise AttributeError("No SSO password or RSA key supplied")
        logged_payload = copy.deepcopy(payload)
        logged_payload['auth']['passwordCredentials']['password'] = "<HIDDEN>"
        LOG.debug('Auth request %s', logged_payload)

        response = requests.post(self.auth_endpoint, data=json.dumps(payload),
                                 headers=headers)
        # TODO(zns): add , verify=config.insecure is True)
        if not response.ok:
            response.raise_for_status()
        results = response.json()
        try:
            return (results['access']['token']['id'],
                    results['access']['token']['expires'])
        except KeyError:
            raise Exception("Authentication result is missing token")

    def _web(self, method, path, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers['X-Auth-Token'] = self.token
        headers['Content-Type'] = 'application/json'
        req = getattr(requests, method)(self.endpoint + path, **kwargs)

        if not req.ok:
            print(req.json())
        req.raise_for_status()
        return req.json()

    def version(self):
        result = self._web('get', '/version')
        return {'client': consts.CLIENT_VERSION, 'server': result['version']}

    def _remove_system_info(self, disc):
        if 'topology' not in disc or 'tiers' not in disc['topology']:
            return disc
        clean = copy.deepcopy(disc)
        for tdata in clean['topology']['tiers'].itervalues():
            if 'resources' in tdata:
                for rdata in tdata['resources'].itervalues():
                    if 'system_info' in rdata:
                        rdata.pop('system_info', None)
        return clean

    def create_discovery(self, account_number=None, account_source=None,
                         netloc=None, dataplane=True, tags=None, force=False):
        if account_number is None and netloc is None:
            raise AttributeError("Account number or netloc required")

        payload = {}
        if account_number:
            payload['account'] = {
                'id': account_number,
                'source': account_source or 'RAXCLOUD',
            }
        if dataplane:
            payload['dataplane'] = bool(dataplane)
        if netloc:
            payload['netloc'] = netloc
        if tags:
            if not isinstance(tags, list):
                raise TypeError("'tags' must be an array.")
            for tag in tags:
                if not isinstance(tag, basestring):
                    raise TypeError("Each tag must be a string, not %s.",
                                    type(tag))
            payload['tags'] = tags
        endpoint = '/v1/discoveries'
        if force:
            endpoint += '?force=1'
        return self._web('post', endpoint, data=json.dumps(payload))

    def get_discovery(self, discovery_id, include_system_info=True):
        result = self._web('get', '/v1/discoveries/%s' % discovery_id)
        if include_system_info:
            return result
        else:
            return self._remove_system_info(result)

    def list_discoveries(self, account_number=None, netloc=None, tags=None,
                         limit=None, offset=None):
        if not account_number and not netloc and not tags:
            raise AttributeError("Account number or netloc or tags required")

        uri = '/v1/discoveries'
        payload = {}
        if account_number:
            payload['account.id'] = account_number
        if netloc:
            payload['netloc'] = netloc
        if tags:
            if not isinstance(tags, list):
                raise TypeError("tags must be a list.")
            payload['tags'] = ','.join(tags)
        if limit:
            payload['limit'] = int(limit)
        if offset:
            payload['offset'] = int(offset)
        return self._web('get', uri, params=payload)


if __name__ == "__main__":
    log_messages_to_stdout()
    client = Waldo(os.environ.get('USERNAME'),
                   password=os.environ.get('PASSWORD'))
