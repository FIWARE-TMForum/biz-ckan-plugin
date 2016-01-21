# -*- coding: utf-8 -*-

# Copyright (c) 2015 - 2016 CoNWeT Lab., Universidad Politécnica de Madrid

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
from urlparse import urlparse, urljoin

from django.core.exceptions import PermissionDenied

from wstore.asset_manager.resource_plugins.plugin import Plugin
from wstore.models import User


class CKANDataset(Plugin):

    def get_request(self, *args, **kwargs):

        try:
            return requests.get(*args, **kwargs)
        except requests.ConnectionError:
            raise PermissionDenied('Invalid resource: The CKAN server is not responding')

    def check_user_is_owner(self, provider, url):

        if not provider.private:
            raise ValueError('FIWARE Organization datasets are not supported')

        user = User.objects.get(username=provider.name)

        # Get CKAN server URL
        parsed_url = urlparse(url)
        ckan_server = parsed_url.scheme + '://' + parsed_url.netloc

        # Extract dataset ID
        # Element 0 is empty
        splitted_path = parsed_url.path.split('/')

        if len(splitted_path) < 3:
            raise PermissionDenied('Invalid resource: The provided URL does not point to a valid CKAN dataset')

        if splitted_path[1] not in ('dataset', 'package'):
            raise PermissionDenied('Invalid resource: The provided URL does not point to a valid CKAN dataset')

        dataset_id = splitted_path[2]

        # Create headers for the requests
        headers = {'X-Auth-token': user.userprofile.access_token}

        # Get dataset metainfo
        meta_url = urljoin(ckan_server, 'api/action/package_show?id=' + dataset_id)
        meta_info_res = self.get_request(meta_url, headers=headers)

        if meta_info_res.status_code != 200:
            error_msg = 'The dataset provided dataset does not exist' if meta_info_res.status_code == 404 else \
                        'The user is not authorized to access the dataset'
            raise PermissionDenied('Invalid resource: %s' % error_msg)

        meta_info = meta_info_res.json()
        user_id = meta_info['result']['creator_user_id']

        # Get user info
        user_url = urljoin(ckan_server, 'api/action/user_show?id=' + user_id)
        user_info_res = self.get_request(user_url, headers=headers)

        if user_info_res.status_code != 200:
            # When the current user cannot access the profile of the owner of dataset,
            # it is assumed that the user is not the owner of the dataset since any user
            # can access its own profile.
            raise PermissionDenied('Invalid resource: The user is not the owner of the dataset')

        user_info = user_info_res.json()

        # Validate owner
        if user_info['result']['name'] != user.username:
            raise PermissionDenied('Invalid resource: The user is not the owner of the dataset')

    def on_pre_product_spec_validation(self, provider, asset_t, media_type, url):
        self.check_user_is_owner(provider, url)

