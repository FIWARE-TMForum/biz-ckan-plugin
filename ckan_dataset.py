# -*- coding: utf-8 -*-

# Copyright (c) 2015 CoNWeT Lab., Universidad Politécnica de Madrid

# This file is part of WStore CKAN plugin.

# WStore CKAN plugin is free software: you can redistribute it
# and/or modify it under the terms of the European Union Public
# Licence (EUPL) as published by the European Commission, either
# version 1.1 of the License, or (at your option) any later
# version.

# WStore CKAN plugin is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the European Union Public Licence for more details.

# You should have received a copy of the European Union Public Licence
# along with WStore CKAN plugin.
# If not, see <https://joinup.ec.europa.eu/software/page/eupl/licence-eupl>.

import requests

from django.core.exceptions import PermissionDenied
from wstore.offerings.resource_plugins.plugin import Plugin
from urlparse import urlparse, urljoin


class CKANDataset(Plugin):

    def check_user_is_owner(self, provider, url):

        parsed_url = urlparse(url)
        ckan_server = parsed_url.scheme + '://' + parsed_url.netloc

        # Extract dataset id
        # Element 0 is empty
        dataset_id = parsed_url.path.split('/')[2]

        # Get dataset metainfo
        meta_url = urljoin(ckan_server, 'api/action/dataset_show?id=' + dataset_id)
        meta_info_res = requests.get(meta_url, headers={'X-Auth-token': provider.userprofile.access_token})

        if meta_info_res.status_code != 200:
            raise PermissionDenied('Invalid resource: The user is not authorized to access the dataset')

        meta_info = meta_info_res.json()
        user_id = meta_info['result']['creator_user_id']

        # Get user info
        user_url = urljoin(ckan_server, 'api/action/user_show?id=' + user_id)
        user_info_res = requests.get(user_url, headers={'X-Auth-token': provider.userprofile.access_token})

        if user_info_res.status_code != 200:
            raise PermissionDenied('Invalid resource: The user is not authorized to access the dataset')

        user_info = user_info_res.json()

        # Validate owner
        if user_info['result']['name'] != provider.username:
            raise PermissionDenied('Invalid resource: The user is not the owner of the dataset')

    def on_pre_create_validation(self, provider, data, file_=None):
        self.check_user_is_owner(provider, data['link'])
        return data

    def on_post_create_validation(self, provider, data, file_=None):
        pass

    def on_pre_create(self, provider, data):
        pass

    def on_post_create(self, resource):
        pass

    def on_pre_update(self, resource):
        pass

    def on_post_update(self, resource):
        pass

    def on_pre_upgrade_validation(self, resource, data, file_=None):
        self.check_user_is_owner(provider, data['link'])
        return data

    def on_post_upgrade_validation(self, resource, data, file_=None):
        pass

    def on_pre_upgrade(self, resource):
        pass

    def on_post_upgrade(self, resource):
        pass

    def on_pre_delete(self, resource):
        pass

    def on_post_delete(self, resource):
        pass
