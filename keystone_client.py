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

import requests
from urlparse import urlparse

from settings import KEYSTONE_HOST, KEYSTONE_PASSWORD, KEYSTONE_USER


class KeystoneClient(object):

    def __init__(self):
        self._login()
        self._url = ''

    def _login(self):
        body = {
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "name": KEYSTONE_USER,
                            "domain": {"name": "Default"},
                            "password": KEYSTONE_PASSWORD
                        }
                    }
                }
            }
        }

        url = KEYSTONE_HOST + '/v3/auth/tokens'
        response = requests.post(url, json=body)

        response.raise_for_status()
        self._auth_token = response.headers['x-subject-token']

    def _get_app_id(self):
        # Get available apps
        apps_url = KEYSTONE_HOST + '/v3/OS-OAUTH2/consumers'
        resp = requests.get(apps_url, headers={
            'X-Auth-Token': self._auth_token
        })

        # Get role id
        resp.raise_for_status()
        apps = resp.json()
        parsed_url = urlparse(self._url)

        for app in apps['consumers']:
            if 'url' in app['extra']:
                app_url = urlparse(app['extra']['url'])
                if app_url.netloc == parsed_url.netloc:
                    app_id = app['id']
                    break
        else:
            raise Exception('The provided app is not registered in keystone')

        return app_id

    def _get_role_id(self, app_id, role_name):
        # Get available roles
        roles_url = KEYSTONE_HOST + '/v3/OS-ROLES/roles'
        resp = requests.get(roles_url, headers={
            'X-Auth-Token': self._auth_token
        })

        # Get role id
        resp.raise_for_status()
        roles = resp.json()

        for role in roles['roles']:
            if role['application_id'] == app_id and role['name'].lower() == role_name.lower():
                role_id = role['id']
                break
        else:
            raise Exception('The provided role is not registered in keystone')

        return role_id

    def _get_role_assign_url(self, role_name, user):
        app_id = self._get_app_id()
        role_id = self._get_role_id(app_id, role_name)
        return KEYSTONE_HOST + '/v3/OS-ROLES/users/' + user.username + '/applications/' + app_id + '/roles/' + role_id

    def set_resource_url(self, url):
        self._url = url

    def check_role(self, role):
        self._get_role_id(self._get_app_id(), role)

    def grant_permission(self, user, role):
        # Get ids
        assign_url = self._get_role_assign_url(role, user)
        resp = requests.put(assign_url, headers={
            'X-Auth-Token': self._auth_token
        })

        resp.raise_for_status()

    def revoke_permission(self, user, role):
        assign_url = self._get_role_assign_url(role, user)
        resp = requests.delete(assign_url, headers={
            'X-Auth-Token': self._auth_token
        })

        resp.raise_for_status()
