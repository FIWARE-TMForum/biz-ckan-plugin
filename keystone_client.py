# -*- coding: utf-8 -*-

# Copyright (c) 2017 - 2018 CoNWeT Lab., Universidad Politécnica de Madrid

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
from django.conf import settings as django_settings

from settings import KEYSTONE_HOST, KEYSTONE_PASSWORD, KEYSTONE_USER, IS_LEGACY_IDM


class KeystoneClient(object):

    def __init__(self):
        self._login()
        self._url = ''

    def _login(self):
        if IS_LEGACY_IDM:
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
        else:
            body = {
                "name": KEYSTONE_USER,
                "password": KEYSTONE_PASSWORD
            }

        url = KEYSTONE_HOST + '/v3/auth/tokens'
        response = requests.post(url, json=body, verify=django_settings.VERIFY_REQUESTS)

        response.raise_for_status()
        self._auth_token = response.headers['x-subject-token']

    def _get_role_id(self, app_id, role_name):
        # Get available roles
        path = '/v3/OS-ROLES/roles' if IS_LEGACY_IDM else '/v1/applications/{}/roles'.format(app_id)
        roles_url = KEYSTONE_HOST + path

        resp = requests.get(roles_url, headers={
            'X-Auth-Token': self._auth_token
        }, verify=django_settings.VERIFY_REQUESTS)

        # Get role id
        resp.raise_for_status()
        roles = resp.json()

        for role in roles['roles']:
            if role['name'].lower() == role_name.lower() and (not IS_LEGACY_IDM or (IS_LEGACY_IDM and role['application_id'] == app_id)):
                role_id = role['id']
                break
        else:
            raise Exception('The provided role is not registered in keystone')

        return role_id

    def _get_role_assign_url(self, app_id, role_name, user):
        role_id = self._get_role_id(app_id, role_name)
        path = '/v3/OS-ROLES/users/{}/applications/{}/roles/{}'.format(user.username, app_id, role_id) if IS_LEGACY_IDM else '/v1/applications/{}/users/{}/roles/{}'.format(app_id, user.username, role_id)
        return KEYSTONE_HOST + path

    def set_resource_url(self, url):
        self._url = url

    def check_role(self, app_id, role):
        self._get_role_id(app_id, role)

    def check_ownership(self, app_id, provider):
        def validate(assingment):
            return assingment['role_id'] == 'provider'

        def validate_legacy(assingment):
            return assingment['application_id'] == app_id and assingment['user_id'] == provider and assingment['role_id'] == 'provider'

        if IS_LEGACY_IDM:
            path = '/v3/OS-ROLES/users/role_assignments'
            role_field = 'role_assignments'
            validator = validate_legacy
        else:
            path = '/v1/applications/{}/users/{}/roles'.format(app_id, provider)
            role_field = 'role_user_assignments'
            validator = validate

        assingments_url = KEYSTONE_HOST + path

        resp = requests.get(assingments_url, headers={
            'X-Auth-Token': self._auth_token
        }, verify=django_settings.VERIFY_REQUESTS)

        resp.raise_for_status()
        assingments = resp.json()

        for assingment in assingments[role_field]:
            if validator(assingment):
                break
        else:
            raise PermissionDenied('You are not the owner of the specified IDM application')

    def grant_permission(self, app_id, user, role):
        # Get ids
        assign_url = self._get_role_assign_url(app_id, role, user)
        method = requests.put if IS_LEGACY_IDM else requests.post

        resp = method(assign_url, headers={
            'X-Auth-Token': self._auth_token,
            'Content-Type': 'application/json'
        }, verify=django_settings.VERIFY_REQUESTS)

        resp.raise_for_status()

    def revoke_permission(self, app_id, user, role):
        assign_url = self._get_role_assign_url(app_id, role, user)
        resp = requests.delete(assign_url, headers={
            'X-Auth-Token': self._auth_token,
            'Content-Type': 'application/json'
        }, verify=django_settings.VERIFY_REQUESTS)

        resp.raise_for_status()
