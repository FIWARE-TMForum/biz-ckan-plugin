# -*- coding: utf-8 -*-

# Copyright (c) 2015 - 2017 CoNWeT Lab., Universidad Politécnica de Madrid

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
from datetime import datetime, timedelta
from urlparse import urlparse, urljoin

from django.core.exceptions import PermissionDenied
from django.conf import settings

from wstore.asset_manager.resource_plugins.plugin import Plugin
from wstore.asset_manager.resource_plugins.plugin_error import PluginError
from wstore.models import User

from settings import UNITS
from umbrella_client import UmbrellaClient
from keystone_client import KeystoneClient


class CKANDataset(Plugin):

    def __init__(self, plugin_model):
        super(CKANDataset, self).__init__(plugin_model)
        self._units = UNITS

    def get_request(self, *args, **kwargs):
        try:
            return requests.get(*args, **kwargs)
        except requests.ConnectionError:
            raise PermissionDenied('Invalid resource: The CKAN server is not responding')

    def get_ckan_info(self, url):
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

        return ckan_server, dataset_id

    def _get_dataset_info(self, url, token):
        # Get CKAN server URL
        ckan_server, dataset_id = self.get_ckan_info(url)

        # Create headers for the requests
        headers = {'X-Auth-token': token}

        # Get dataset metainfo
        meta_url = urljoin(ckan_server, 'api/action/package_show?id=' + dataset_id)
        meta_info_res = self.get_request(meta_url, headers=headers)

        if meta_info_res.status_code != 200:
            error_msg = 'The dataset provided dataset does not exist' if meta_info_res.status_code == 404 else \
                        'The user is not authorized to access the dataset'
            raise PermissionDenied('Invalid resource: %s' % error_msg)

        return meta_info_res.json()

    def check_user_is_owner(self, provider, url):

        if not provider.private:
            raise ValueError('FIWARE Organization datasets are not supported')

        user = User.objects.get(username=provider.name)

        meta_info = self._get_dataset_info(url, user.userprofile.access_token)
        user_id = meta_info['result']['creator_user_id']

        # Get user info
        # Get CKAN server URL
        ckan_server, dataset_id = self.get_ckan_info(url)
        # Create headers for the requests
        headers = {'X-Auth-token': user.userprofile.access_token}

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

    def _get_api_client(self, url):
        parsed_url = urlparse(url)
        server = '{}://{}'.format(parsed_url.scheme, parsed_url.netloc)

        return UmbrellaClient(server)

    def _check_dataset_api(self, url, name):
        parsed_url = urlparse(url)
        server = '{}://{}'.format(parsed_url.scheme, parsed_url.netloc)

        umbrella_client = UmbrellaClient(server)
        umbrella_client.validate_service(parsed_url.path, name)

    def on_post_product_spec_validation(self, provider, asset):
        # Read CKAN dataset resources in order to determine the broker URLs
        token = User.objects.get(username=provider.name).userprofile.access_token
        dataset_info = self._get_dataset_info(asset.get_url(), token)['result']

        for resource in dataset_info['resources']:
            # If the CKAN resource is a URL, save it in order to enable activation and accounting
            if 'url' in resource and len(resource['url']) > 0:

                self._check_dataset_api(resource['url'], resource['name'])

                if 'resources' not in asset.meta_info:
                    asset.meta_info['resources'] = []

                asset.meta_info['resources'].append(resource['url'])

                # Check that the provided role is valid for the given API service
                client = self._get_api_client(resource['url'])
                client.check_role(asset.meta_info['role'])

        # TODO: Validate that the user is also the owner of the API
        asset.save()

    def on_post_product_offering_validation(self, asset, product_offering):
        # Validate that the pay-per-use model (if any) is supported by the backend
        if 'productOfferingPrice' in product_offering:
            has_usage = False
            supported_units = [unit['name'].lower() for unit in self._units]

            for price_model in product_offering['productOfferingPrice']:
                if price_model['priceType'] == 'usage':
                    has_usage = True

                    if price_model['unitOfMeasure'].lower() not in supported_units:
                        raise PluginError('Unsupported accounting unit ' +
                                          price_model['unit'] + '. Supported units are: ' + ','.join(supported_units))

            # Validate that for static datasets usage model is not defined
            if has_usage and 'resources' not in asset.meta_info or not len(asset.meta_info['resources']):
                raise PluginError('Static CKAN datasets cannot be monetized under usage models')

    def _manage_notification(self, path, asset, order):
        # Build notification URL
        ckan_server, dataset_id = self.get_ckan_info(asset.get_url())
        notification_url = urljoin(ckan_server, path)

        # Build notification data
        data = {
            'customer_name': order.owner_organization.name,
            'resources': [{
                'url': asset.get_url()
            }]
        }

        # Notify the dataset acquisition to CKAN
        headers = {'Content-type': 'application/json'}
        response = requests.post(
            notification_url,
            json=data,
            headers=headers,
            cert=(settings.NOTIF_CERT_FILE, settings.NOTIF_CERT_KEY_FILE)
        )
        response.raise_for_status()

    def on_product_acquisition(self, asset, contract, order):
        # Activate API resources
        if 'resources' in asset.meta_info:
            for resource in asset.meta_info['resources']:
                keystone_client = KeystoneClient()
                keystone_client.grant_permission(order.customer, resource, asset.meta_info['role'])

                # Set the role in BAE scope
                keystone_client.grant_permission(order.customer, settings.SITE, asset.meta_info['role'])

                client = self._get_api_client(resource)
                client.update_user_role(order.customer.email, asset.meta_info['role'])

        # Activate CKAN dataset
        self._manage_notification('/api/action/package_acquired', asset, order)

    def on_product_suspension(self, asset, contract, order):
        # Suspend API Resources
        if 'resources' in asset.meta_info:
            for resource in asset.meta_info['resources']:
                keystone_client = KeystoneClient()
                keystone_client.revoke_permission(order.customer, resource, asset.meta_info['role'])

                # Revoke the role in BAE scope
                keystone_client.revoke_permission(order.customer, settings.SITE, asset.meta_info['role'])

                client = self._get_api_client(resource)
                client.revoke_user_role(order.customer.email, asset.meta_info['role'])

        # Suspend CKAN dataset
        self._manage_notification('/api/action/revoke_access', asset, order)

    ####################################################################
    #######################  Accounting Handlers #######################
    ####################################################################

    def get_usage_specs(self):
        return self._units

    def get_pending_accounting(self, asset, contract, order):
        accounting = []
        last_usage = None
        # Read pricing model to know the query to make
        if 'pay_per_use' in contract.pricing_model:
            unit = contract.pricing_model['pay_per_use'][0]['unit']

            # Read the date of the last SDR
            if contract.last_usage is not None:
                start_at = unicode(contract.last_usage.isoformat()).replace(' ', 'T') + 'Z'
            else:
                # The maximum time between refreshes is 30 days, so in the worst case
                # consumption started 30 days ago
                start_at = unicode((datetime.utcnow() - timedelta(days=31)).isoformat()).replace(' ', 'T') + 'Z'

            # Retrieve pending usage
            # TODO: Support more accounting units
            if unit.lower() == 'api call':
                last_usage = datetime.utcnow()
                end_at = unicode(last_usage.isoformat()).replace(' ', 'T') + 'Z'

                # Check the accumulated usage for all the resources of the dataset
                for resource in asset.meta_info['resources']:
                    client = self._get_api_client(resource)
                    accounting.extend(client.get_drilldown_by_service(order.customer.email, resource, start_at, end_at))

        return accounting, last_usage
