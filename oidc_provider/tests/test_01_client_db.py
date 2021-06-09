import logging
import random
import string

from django.test import TestCase
from django.utils import timezone
from oidc_provider.models import OidcRelyingParty


logger = logging.getLogger('oidc_provider')


def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


CLIENT_ID = randomString()
CLIENT_TEST = {
    'client_id': '{}'.format(CLIENT_ID),
    'client_salt': '6flfsj0Z',
    'registration_access_token': 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY',
    'registration_client_uri': f'https://127.0.0.1:8000/registration_api?client_id={CLIENT_ID}',
    'client_id_issued_at': 1575460012,
    'client_secret': '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1',
    'client_secret_expires_at': 1575892012,
    'application_type': 'web',
    'contacts': ['ops@example.com'],
    'token_endpoint_auth_method': 'client_secret_basic',
    'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
    'redirect_uris': [('https://127.0.0.1:8099/authz_cb/django_oidc_op', {})],
    'post_logout_redirect_uris': [('https://127.0.0.1:8099', None)],
    'response_types': ['code'],
    'grant_types': ['authorization_code']
}

CDB = {CLIENT_ID: CLIENT_TEST}


class TestOidcRelyingParty(TestCase):
    rp = randomString().upper()

    def test_create_rp(self):
        now = timezone.localtime()
        self.client = OidcRelyingParty.objects.create(
            client_id=self.rp,
            client_secret_expires_at=now,
            client_id_issued_at=now,
            is_active=True
        )
        logger.info('Created and fetched RP: {}'.format(self.client))

    def test_import_from_cdb(self):
        OidcRelyingParty.import_from_cdb(CDB)
