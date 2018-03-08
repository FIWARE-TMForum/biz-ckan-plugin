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

from django.core.exceptions import PermissionDenied

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

    def _get_role_assign_url(self, app_id, role_name, user):
        role_id = self._get_role_id(app_id, role_name)
        return KEYSTONE_HOST + '/v3/OS-ROLES/users/' + user.username + '/applications/' + app_id + '/roles/' + role_id

    def set_resource_url(self, url):
        self._url = url

    def check_role(self, app_id, role):
        self._get_role_id(app_id, role)

    def check_ownership(self, app_id, provider):
        assingments_url = KEYSTONE_HOST + '/v3/OS-ROLES/users/role_assignments'

        resp = requests.get(assingments_url, headers={
            'X-Auth-Token': self._auth_token
        })

        resp.raise_for_status()
        assingments = resp.json()

        for assingment in assingments['role_assignments']:
            if assingment['application_id'] == app_id and assingment['user_id'] == provider and assingment['role_id'] == 'provider':
                break
        else:
            raise PermissionDenied('You are not the owner of the specified IDM application')

    def grant_permission(self, app_id, user, role):
        # Get ids
        assign_url = self._get_role_assign_url(app_id, role, user)
        resp = requests.put(assign_url, headers={
            'X-Auth-Token': self._auth_token
        })

        resp.raise_for_status()

    def revoke_permission(self, app_id, user, role):
        assign_url = self._get_role_assign_url(app_id, role, user)
        resp = requests.delete(assign_url, headers={
            'X-Auth-Token': self._auth_token
        })

        resp.raise_for_status()
