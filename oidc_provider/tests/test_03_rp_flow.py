import base64
import datetime
import logging
import re
import urllib


from django.contrib.auth import get_user_model
from django.test import Client
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from oidc_provider.models import OidcRelyingParty
from oidc_provider.utils import decode_token, dt2timestamp, timestamp2dt

logger = logging.getLogger('oidc_provider')

CLIENT_1_ID = 'jbxedfmfyc'
CLIENT_1_PASSWD = '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1'
CLIENT_1_RAT = 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY'
CLIENT_1_SESLOGOUT = 'https://127.0.0.1:8099/session_logout/django_provider'
CLIENT_1 = {
    'jbxedfmfyc': {
        'client_id': CLIENT_1_ID,
        'client_salt': '6flfsj0Z',
        'registration_access_token': CLIENT_1_RAT,
        'registration_client_uri': 'https://127.0.0.1:8000/registration_api?client_id=jbxedfmfyc',
        'client_id_issued_at': timezone.localtime().timestamp(),
        'client_secret': CLIENT_1_PASSWD,
        'client_secret_expires_at': (timezone.localtime() + timezone.timedelta(days=1)).timestamp(),
        'application_type': 'web',
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        # 'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
        'redirect_uris': [('https://127.0.0.1:8099/authz_cb/django_provider', {})],
        'post_logout_redirect_uris': [(CLIENT_1_SESLOGOUT, None)],
        'response_types': ['code'],
        'grant_types': ['authorization_code'],
        'allowed_scopes': ['openid', 'profile', 'email', 'offline_access']
    }
}
CLIENT_1_BASICAUTHZ = f'Basic {base64.b64encode(f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}".encode()).decode()}'
ACCESS_TOKEN = "eyJhbGciOiJFUzI1NiIsImtpZCI6Ik16UldNamhvUmt0UVVYWklkRTFSZUV0cE5GRkJTMFIwVEc1T05WVlJUazltVkZOWFFqVm9VMHBQWncifQ.eyJzY29wZSI6IFsib3BlbmlkIiwgInByb2ZpbGUiLCAiZW1haWwiLCAiYWRkcmVzcyIsICJwaG9uZSIsICJvZmZsaW5lX2FjY2VzcyJdLCAiYXVkIjogWyI2TXdoRzNWRl9BWml5U2huSHlteWxRIl0sICJqdGkiOiAiYmY5N2I0MThjOTZlMTFlYmEwYjAzZjlmOWRhN2RhNjkiLCAiY2xpZW50X2lkIjogIjZNd2hHM1ZGX0FaaXlTaG5IeW15bFEiLCAic3ViIjogIjZNd2hHM1ZGX0FaaXlTaG5IeW15bFEiLCAic2lkIjogIlowRkJRVUZCUW1kM1ZITlRibmx2Y0dOdFNrbFVRazFvZDBSWlUzcGFSR2hmT1hkWFNtaElWelZhVW05NmFHWkxhRVU1Y2xSc1FXVkJSMjlWVVZCWFZXVjFOazlCVERrNVN6TkZWMWRZTTBkaVVtbFZMVVV5ZVdKMVdXOUZPVWxKVDBoZk4zcDFkWEZMZDI1MGMwUm1Ua0YzUWpWVk4yNXdkekZYTUU1MkxWZFhjMkp5Y1VwQ2RFZG5jRTFXYUc1eGFIUjNkVGRCVkcxWFQyNURSR1kwZFZScU0yOWlZMFpYTTJnNFRVNWFObmRDVGxabFdFbEJRVkpVZHpKeldrOHhWWHBTWWtKMVdFY3phRXBQVTBKU1VXSmtaaTFVV1ZrMGEwVTBhWFpDZGxONFJ6UnFaWE5RWTBGTVRqaDZOek56YWpkTGFsaFBZejA9IiwgInRva2VuX2NsYXNzIjogImFjY2Vzc190b2tlbiIsICJpc3MiOiAiaHR0cHM6Ly8xMjcuMC4wLjE6ODAwMCIsICJpYXQiOiAxNjIzMjc2MzA2LCAiZXhwIjogMTYyMzI3OTkwNn0.tbJVJVKIgqhkD8cDldteeQY3FyLgckvggD-dWqjHbHB2HRo0lqv17DHGOOs4O5HwY3YMLG_yibgz8ncaSj6MYw"


class TestOidcRPFlow(TestCase):
    def setUp(self):
        self.client = Client()

    def _test_discovery_provider(self):
        url = reverse('oidc_provider:_well_known',
                      kwargs={'service': 'openid-configuration'}
                      )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(type(response.json()), dict)

    def test_registration(self):
        url = reverse('oidc_provider:registration')
        data = {
            "application_type": "web",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "subject_type": "pairwise",
            "token_endpoint_auth_method": "client_secret_basic",
            # "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA-OAEP",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt#qpXaRLh_n93TT",
                "https://client.example.org/rf.txt",
            ],
            "post_logout_redirect_uris": [
                "https://rp.example.com/pl?foo=bar",
                "https://rp.example.com/pl",
            ],
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(type(response.json()), dict)

        # test read registration api
        OidcRelyingParty.import_from_cdb(CLIENT_1)
        url = reverse('oidc_provider:registration_read')
        headers = {
            'HTTP_AUTHORIZATION': f"Bearer {response.json()['registration_access_token']}"
        }
        response = self.client.get(
            url,
            {'client_id': response.json()['client_id']},
            **headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('client_secret', response.json())

    def test_authz(self):
        # without dynamic client registration here ...
        OidcRelyingParty.import_from_cdb(CLIENT_1)
        data = {
            'redirect_uri': 'https://127.0.0.1:8099/authz_cb/django_provider',
            'scope': 'openid profile email address phone offline_access',
            'response_type': 'code',
            'nonce': 'd0GjnvG2zVZmnbyBzioXOFXU',
            'state': 'AREIA28Qh8xICz4j3rSc2tSQkV3QbFvx',
            'code_challenge': 'Mbp5kPfcaQ6MVj8MUcjcjHEcbwuNY5GBrG5HqJLgjCg',
            'code_challenge_method': 'S256',
            'client_id': 'jbxedfmfyc',
            'prompt': 'consent'
        }
        url = reverse('oidc_provider:authorization')
        response = self.client.get(url, data=data)
        print(f'Authorization request: {response.request}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('form action="/oidcop/verify/oidc_user_login/',
                      response.content.decode())

        # yes I do a form submission now
        auth_code = re.search(
            'value="(?P<token>[a-zA-Z\-\.\_0-9]*)"',
            response.content.decode()).groupdict()['token']

        auth_dict = {
            'username': 'test',
            'password': 'testami18_WRONG',
            'token': auth_code
        }

        user = get_user_model().objects.create(
            username='test',
            email='me@my.self',
            is_staff=1,
            is_superuser=1)
        user.set_password('testami18')
        user.save()

        url = reverse('oidc_provider:verify_user')
        response = self.client.post(url, data=auth_dict)
        self.assertEqual(response.status_code, 403)

        auth_dict['password'] = 'testami18'
        response = self.client.post(url, data=auth_dict)

        # put the right cookie in
        _cookies = response.cookies

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
        self.assertIn('access_token', response.json())

        _id_token = response.json()['id_token']

        # refresh token
        data = {
            "grant_type" : "refresh_token",
            "client_id" : f"{CLIENT_1_ID}",
            "client_secret" : f"{CLIENT_1_PASSWD}",
            "refresh_token" : f"{response.json()['refresh_token']}"
        }
        response = self.client.post(url, data=data, **headers)
        self.assertIn('access_token', response.json())

        # userinfo
        url = reverse('oidc_provider:userinfo')
        headers = {
            'HTTP_AUTHORIZATION': f"Bearer {response.json()['access_token']}"
        }
        response = self.client.get(url, **headers)

        # test admin
        self.client.login(username='test', password='testami18')
        url = reverse('admin:oidc_provider_oidcsession_change',
                      kwargs={'object_id': 1})
        response = self.client.get(url)
        # end admin

        # session logout
        data = {
            'id_token_hint': _id_token,
            'post_logout_redirect_uri': 'https://127.0.0.1:8099/session_logout/django_provider',
            'state': _data['state'][0]
        }
        headers = {
            'HTTP_COOKIE': f"oidc_op='{_cookies.get('oidc_op').value}'"
        }
        url = reverse('oidc_provider:session')
        response = self.client.get(
            url, data=data, cookies=_cookies, **headers
        )
        self.assertEqual(response.status_code, 302)

        # verify logout
        url = reverse('oidc_provider:verify_logout')
        _qs = response.url.split('?')[1]
        response = self.client.get(f"{url}?{_qs}")
        self.assertIn('type="hidden" name="sjwt"', response.content.decode())

        # rp logout
        url = reverse('oidc_provider:rp_logout')
        data = {
            'sjwt': [urllib.parse.parse_qs(_qs)['sjwt'][0]],
            'logout': ['yes']
        }
        response = self.client.post(url, data=data, **headers)
        self.assertEqual(response.status_code, 302)
        self.assertIn(CLIENT_1_SESLOGOUT, response.url)
        self.assertIn(_data['state'][0], response.url)


    def test_utils(self):
        decode_token(ACCESS_TOKEN)

        now = datetime.datetime.now()
        ts = dt2timestamp(now)
        timestamp2dt(ts)
