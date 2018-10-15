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

from os import environ

UNITS = [{
    'name': 'Api call',
    'description': 'The final price is calculated based on the number of calls made to the API'
}]

UMBRELLA_SERVER = 'https://umbrella.docker:8443'
UMBRELLA_KEY = 'LWmOjZMTuaZp5BwNI3GsNsdsR6Sq3YqBHUcUj9Fw'
UMBRELLA_ADMIN_TOKEN = 'JDLlA0iRw5lYbT1ucKcP3AwT6eGtbsBgqoUf2RyV'

KEYSTONE_USER = 'idm'
KEYSTONE_PASSWORD = 'idm'
KEYSTONE_HOST = ''
IS_LEGACY_IDM = False

# Supported options are bearer for Authorization: Bearer TOKEN, or x-auth for X-Auth-Token: TOKEN
CKAN_TOKEN_TYPE = 'bearer'

# =====================================================
# READ environ to check if settings has to be overriden

UMBRELLA_SERVER = environ.get('BAE_ASSET_UMBRELLA_SERVER', UMBRELLA_SERVER)
UMBRELLA_KEY = environ.get('BAE_ASSET_UMBRELLA_KEY', UMBRELLA_KEY)
UMBRELLA_ADMIN_TOKEN = environ.get('BAE_ASSET_UMBRELLA_TOKEN', UMBRELLA_ADMIN_TOKEN)

KEYSTONE_USER = environ.get('BAE_ASSET_IDM_USER', KEYSTONE_USER)
KEYSTONE_PASSWORD = environ.get('BAE_ASSET_IDM_PASSWORD', KEYSTONE_PASSWORD)
KEYSTONE_HOST = environ.get('BAE_ASSET_IDM_HOST', KEYSTONE_HOST)

is_legacy = environ.get('BAE_ASSET_LEGACY_IDM', None)
if is_legacy is not None:
    IS_LEGACY_IDM = is_legacy == "True"

# Supported options are bearer for Authorization: Bearer TOKEN, or x-auth for X-Auth-Token: TOKEN
CKAN_TOKEN_TYPE = environ.get('BAE_ASSET_TOKEN_TYPE', CKAN_TOKEN_TYPE)
