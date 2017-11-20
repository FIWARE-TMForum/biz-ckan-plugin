# -*- coding: utf-8 -*-

# Copyright (c) 2017 CoNWeT Lab., Universidad Politécnica de Madrid

# This file is part of BAE CKAN plugin.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import json
import requests
import urllib
from datetime import datetime
from urlparse import urljoin, urlparse

from django.core.exceptions import PermissionDenied

from wstore.asset_manager.resource_plugins.plugin_error import PluginError

from settings import UMBRELLA_ADMIN_TOKEN, UMBRELLA_KEY


class UmbrellaClient(object):

    def __init__(self, server):
        self._server = server

    def _make_request(self, path, method, **kwargs):
        url = urljoin(self._server, path)
        try:
            resp = method(url, **kwargs)
        except requests.ConnectionError:
            raise PermissionDenied('Invalid resource: API Umbrella server is not responding')

        if resp.status_code == 404:
            raise PluginError('The provided Umbrella resource does not exist')
        elif resp.status_code != 200:
            raise PluginError('Umbrella gives an error accessing the provided resource')

        return resp

    def _get_request(self, path):
        resp = self._make_request(path, requests.get, headers={
            'X-Api-Key': UMBRELLA_KEY,
            'X-Admin-Auth-Token': UMBRELLA_ADMIN_TOKEN
        }, verify=False)

        return resp.json()

    def _put_request(self, path, body):
        self._make_request(path, requests.get, json=body, headers={
            'X-Api-Key': UMBRELLA_KEY,
            'X-Admin-Auth-Token': UMBRELLA_ADMIN_TOKEN
        }, verify=False)

    def validate_service(self, path, name):
        err_msg = 'The resource {} included in the dataset is not supported. ' \
                  'Only services protected by API Umbrella are supported'.format(name)

        path_parts = path.split('/')
        if len(path_parts) < 2:
            # API umbrella resources include a path for matching the service
            raise PluginError(err_msg)

        initial_path = path_parts[1]

        apis = self._get_request('/api-umbrella/v1/apis.json?search[value]={}&search[regex]=false'.format(initial_path))
        for api in apis['data']:
            if api['frontend_prefixes'].startswith('/' + initial_path):
                break
        else:
            # None of the retrieved APIs has the provided path in umbrella server
            raise PluginError(err_msg)

    def check_role(self, role):
        # Check that the provided role already exists, in order to avoid users creating new roles
        # using this service
        existing_roles = self._get_request('api-umbrella/v1/user_roles')
        for existing_role in existing_roles['user_roles']:
            if existing_role['id'] == role:
                break
        else:
            raise PluginError('The role {} does not exist in API Umbrella instance'.format(role))

    def _get_user_model(self, email):
        # Search users using the email field
        users = self._get_request('/api-umbrella/v1/users?search[value]={}'.format(email))

        for user_result in users['data']:
            if user_result['email'] == email:
                user_id = user_result['id']
                break
        else:
            raise PluginError('There is not any user registered in Umbrella instance with email: {}'.format(email))

        # Get user model
        return self._get_request('/api-umbrella/v1/users/{}'.format(user_id))

    def _filter_roles(self, user_model, role):
        new_roles = []
        if user_model['user']['roles'] is not None:
            # Parse existing roles
            new_roles = [user_role for user_role in user_model['user']['roles'] if user_role != role]

        return new_roles

    def grant_permission(self, user, role):
        self.check_role(role)
        user_model = self._get_user_model(user.email)

        # Update user roles
        new_roles = self._filter_roles(user_model, role).append(role)

        user_model['user']['roles'] = new_roles

        self._put_request('/api-umbrella/v1/users/{}'.format(user_model['user']['id']), user_model)

    def revoke_permission(self, user, role):
        self.check_role(role)
        user_model = self._get_user_model(user.email)
        user_model['user']['roles'] = self._filter_roles(user_model, role)
        self._put_request('/api-umbrella/v1/users/{}'.format(user_model['user']['id']), user_model)

    def _get_rule(self, field, value):
        return {
            'id': field,
            'field': field,
            'type': 'string',
            'input': 'text',
            'operator': 'equal',
            'value': value
        }

    def get_drilldown_by_service(self, email, service, start_at, end_at):
        parsed_url = urlparse(service)
        rules = [
            self._get_rule('user_email', email), self._get_rule('request_path', parsed_url.path)]

        if len(parsed_url.query):
            rules.append(self._get_rule('request_url_query', parsed_url.query))

        query = {
            'condition': 'AND',
            'rules': rules,
            'valid': True
        }

        query_param = urllib.quote(json.dumps(query), safe='')
        prefix = '2/{}/{}/'.format(parsed_url.netloc, parsed_url.path.split('/')[1])

        query_string = '?start_at={}&end_at={}&interval=day&query={}&prefix={}&beta_analytics=false'.format(
            start_at, end_at, query_param, prefix
        )
        stats = self._get_request('/api-umbrella/v1/analytics/drilldown.json' + query_string)['hits_over_time']

        accounting = []
        for daily_stat in stats['rows']:
            if len(daily_stat['c']) > 1 and daily_stat['c'][1]['v'] > 0:
                date = datetime.strptime(daily_stat['c'][0]['f'], '%a, %b %d, %Y')
                accounting.append({
                    'unit': 'api call',
                    'value': daily_stat['c'][1]['f'],
                    'date': unicode(date.isoformat()).replace(' ', 'T') + 'Z'
                })

        return accounting
