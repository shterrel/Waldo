# pylint: disable=C0103,R0904

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

"""Tests for Waldo Client."""

import datetime
import json
import mock
import unittest
import uuid

from waldoc import client


class TestWaldoClient(unittest.TestCase):

    def setUp(self):
        self.fake_token = uuid.uuid4().hex

    def create_patch(self, name, path):
        patcher = mock.patch.object(name, path)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def test_waldo_token_cache_future_expiration_date_returns_token(self):
        file_data = {
            'user': 'bob',
            'token': self.fake_token,
            'expires': str(
                datetime.datetime.now() + datetime.timedelta(days=14)),
        }
        mocked = mock.MagicMock(return_value=json.dumps(file_data))
        with mock.patch.object(client, 'read_file', mocked):
                self.assertEqual(client.waldo_token_cache(), self.fake_token)

    def test_waldo_token_cache_expired_token_returns_none(self):
        file_data = {
            'user': 'bob',
            'token': self.fake_token,
            'expires': str(
                datetime.datetime.now() + datetime.timedelta(days=-1)),
        }
        mocked = mock.MagicMock(return_value=json.dumps(file_data))
        with mock.patch.object(client, 'read_file', mocked):
            self.assertEqual(client.waldo_token_cache(), None)

    def test_waldo_token_cache_invalid_field_invalidates_cache(self):
        file_data = {
            'user': 'bob',
            'token': self.fake_token,
            'expires': str(
                datetime.datetime.now() + datetime.timedelta(days=14)),
            'INVALID-FIELD-NAME': 'foo',
        }
        mocked = mock.MagicMock(return_value=json.dumps(file_data))
        with mock.patch.object(client, 'read_file', mocked):
            self.assertEqual(client.waldo_token_cache(), None)

    def test_waldo_token_cache_missing_expires_field_invalidates_cache(self):
        file_data = {
            'user': 'bob',
            'token': self.fake_token,
        }
        mocked = mock.MagicMock(return_value=json.dumps(file_data))
        with mock.patch.object(client, 'read_file', mocked):
            self.assertEqual(client.waldo_token_cache(), None)

    def test_hammertime_token_cache_two_fields_is_valid(self):
        file_data = "%s|bob" % self.fake_token
        mocked = mock.MagicMock(return_value=file_data)
        with mock.patch.object(client, 'read_file', mocked):
            self.assertEqual(client.hammertime_token_cache(), self.fake_token)

    def test_hammertime_token_cache_three_fields_invalidates_cache(self):
        file_data = "%s|bob|third-field" % self.fake_token
        mocked = mock.MagicMock(return_value=file_data)
        with mock.patch.object(client, 'read_file', mocked):
            self.assertEqual(client.hammertime_token_cache(), None)

    def test_no_secrets_raises_attribute_error(self):
        mocked = mock.MagicMock(return_value="{}")
        with mock.patch.object(client, 'read_file', mocked):
            with self.assertRaises(AttributeError):
                client.Waldo('bob')

    def test_get_token_returns_hammertimes_token(self):
        mock_waldo_token_cache = self.create_patch(client, 'waldo_token_cache')
        mock_waldo_token_cache.return_value = None
        mock_hammertime_token_cache = self.create_patch(
            client, 'hammertime_token_cache')
        mock_hammertime_token_cache.return_value = self.fake_token

        c = client.Waldo('bob')
        self.assertEqual(c.token, self.fake_token)

    def test_get_token_returns_waldo_cache_token(self):
        mock_waldo_token_cache = self.create_patch(client, 'waldo_token_cache')
        mock_waldo_token_cache.return_value = self.fake_token
        mock_hammertime_token_cache = self.create_patch(
            client, 'hammertime_token_cache')
        mock_hammertime_token_cache.return_value = None

        c = client.Waldo('bob')
        self.assertEqual(c.token, self.fake_token)

if __name__ == '__main__':
    unittest.main()
