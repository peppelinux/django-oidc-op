import datetime
import random
import string
import pytz

from django.test import TestCase
from oidc_op.db_interfaces import *
from oidc_op.models import TIMESTAMP_FIELDS, OidcRelyingParty


def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


class TestRP(TestCase):
    rp = randomString().upper()
    cdb = OidcClientDatabase()
    now = pytz.utc.localize(datetime.datetime.utcnow())

    def setUp(self):
        rp = OidcRelyingParty.objects.create(client_id = self.rp,
                                             client_secret_expires_at = self.now,
                                             client_id_issued_at = self.now,
                                             is_active=True)
        self.client = self.cdb[self.rp]
        print('Created RP: {}'.format(self.client))

    def test_get_timestamp(self):
        for key in TIMESTAMP_FIELDS:
            value = self.client[key]
            assert isinstance(value, float)

    def test_set_timestamp(self):
        for key in TIMESTAMP_FIELDS:
            dt_value = self.now+datetime.timedelta(minutes=-60)
            self.client[key] = datetime.datetime.timestamp(dt_value)
            assert isinstance(self.client[key], float)
