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

UNITS = [{
    'name': 'Api call',
    'description': 'The final price is calculated based on the number of calls made to the API'
}]

# Authorization can be done using the FIWARE IdM or directly with API Umbrella roles
AUTH_METHOD = 'idm'

UMBRELLA_KEY = 'LWmOjZMTuaZp5BwNI3GsNsdsR6Sq3YqBHUcUj9Fw'
UMBRELLA_ADMIN_TOKEN = 'JDLlA0iRw5lYbT1ucKcP3AwT6eGtbsBgqoUf2RyV'

KEYSTONE_USER = 'idm'
KEYSTONE_PASSWORD = 'idm'
KEYSTONE_HOST = ''
