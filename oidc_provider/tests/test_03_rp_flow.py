import base64
import json
import logging
import os
import re
import urllib

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from django.contrib.auth import get_user_model
from django.test import Client
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from oidc_provider.models import OidcRelyingParty

logger = logging.getLogger('oidc_provider')

CLIENT_1_ID = 'jbxedfmfyc'
CLIENT_1_PASSWD = '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1'
CLIENT_1 = {
    'jbxedfmfyc': {
        'client_id': CLIENT_1_ID,
        'client_salt': '6flfsj0Z',
        'registration_access_token': 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY',
        'registration_client_uri': 'https://127.0.0.1:8000/registration_api?client_id=jbxedfmfyc',
        'client_id_issued_at': timezone.localtime().timestamp(),
        'client_secret': CLIENT_1_PASSWD,
        'client_secret_expires_at': (timezone.localtime() + timezone.timedelta(days=1)).timestamp(),
        'application_type': 'web',
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        # 'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
        'redirect_uris': [('https://127.0.0.1:8099/authz_cb/django_provider', {})],
        'post_logout_redirect_uris': [('https://127.0.0.1:8099', None)],
        'response_types': ['code'],
        'grant_types': ['authorization_code']
    }
}

CLIENT_1_BASICAUTHZ = f'Basic {base64.b64encode(f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}".encode()).decode()}'

class TestOidcRPFlow(TestCase):
    def setUp(self):
        self.client = Client()

    def test_discovery_provider(self):
        url = reverse('oidc_provider:_well_known',
                      kwargs={'service':'openid-configuration'}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(type(response.json()), dict)

    def test_registration(self):
        url = reverse('oidc_provider:registration')
        data = {
            "application_type": "web",
            "response_types": ["code"],
            "contacts": ["ops@example.com"],
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_uris": ["https://127.0.0.1:8099/authz_cb/django_provider"],
            "post_logout_redirect_uris": ["https://127.0.0.1:8099/session_logout/django_provider"],
            # "jwks_uri": "https://127.0.0.1:8099/static/jwks.json",
            "frontchannel_logout_uri": "https://127.0.0.1:8099/fc_logout/django_provider",
            "backchannel_logout_uri": "https://127.0.0.1:8099/bc_logout/django_provider",
            "grant_types": ["authorization_code"]
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(type(response.json()), dict)

    def test_authz(self):
        client = OidcRelyingParty.import_from_cdb(CLIENT_1)
        data = {
            'redirect_uri' : 'https://127.0.0.1:8099/authz_cb/django_provider',
            'scope' : 'openid profile email address phone offline_access',
            'response_type' : 'code',
            'nonce' : 'd0GjnvG2zVZmnbyBzioXOFXU',
            'state' : 'AREIA28Qh8xICz4j3rSc2tSQkV3QbFvx',
            'code_challenge' : 'Mbp5kPfcaQ6MVj8MUcjcjHEcbwuNY5GBrG5HqJLgjCg',
            'code_challenge_method' : 'S256',
            'client_id' : 'jbxedfmfyc',
            'prompt' : 'consent'
        }
        url = reverse('oidc_provider:authorization')
        response = self.client.get(url, data=data)
        print(f'Authorization request: {response.request}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('form action="/oidcop/verify/oidc_user_login/', response.content.decode())

        # yes I do a form submission now
        auth_code = re.search(
            'value="(?P<token>[a-zA-Z\-\.\_0-9]*)"',
            response.content.decode()).groupdict()['token']

        auth_dict = {
            'username': 'test',
            'password': 'testami18',
            'token': auth_code
        }

        user = get_user_model().objects.create(
                                        username='test',
                                        email = 'me@my.self')
        user.set_password('testami18')
        user.save()
        # auth_url = ''.join((issuer_fqdn, auth_url))
        url = reverse('oidc_provider:verify_user')
        response = self.client.post(url, data=auth_dict)

        self.assertEqual(response.status_code, 302)
        print(f'Authorization code redirect: {response.url}')

        _data = urllib.parse.parse_qs(response.url.split('?')[1])

        data = {
            'grant_type': 'authorization_code',
            'redirect_uri': data['redirect_uri'],
            'client_id': CLIENT_1_ID,
            'state': _data['state'],
            'code': _data['code'],
            'code_verifier': '8TuTiNE18VhP2B3wtxfz8pjr1Y8bAxNjJ3VE7GjVHVWPCZ6mdYEnkbaYRquw9Fna'
        }

        url = reverse('oidc_provider:token')
        headers = {
           'HTTP_AUTHORIZATION': CLIENT_1_BASICAUTHZ
        }
        response = self.client.post(url, data=data, **headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn('refresh_token', response.json())
