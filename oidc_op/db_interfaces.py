import datetime
import urllib
import pytz

from . models import (OidcRelyingParty,
                      OidcRPResponseType,
                      OidcRPGrantType,
                      OidcRPContact,
                      OidcRPRedirectUri,
                      TIMESTAMP_FIELDS)


class OidcClientDatabase(object):
    """
    Adaptation of a Django model as it would been a dict
    """
    model = OidcRelyingParty

    def __contains__(self, key):
        if self.model.objects.filter(client_id=key).first():
            return 1

    def __iter__(self):
        values = self.model.objects.all().values_list('client_id')
        self.clients = [cid[0] for cid in values]
        for value in (self.clients):
            yield value

    def get(self, key, excp=None):
        client = self.model.objects.filter(client_id=key,
                                           is_active=True).first()
        if not client:
            return excp
        return client.copy()

    def __getitem__(self, key):
        value = self.get(key)
        if not value:
            raise KeyError
        return value

    def __setitem__(self, key, value):
        dv = value.copy()

        for k,v in dv.items():
            if isinstance(v, int) or isinstance(v, float):
                if k in TIMESTAMP_FIELDS:
                    dt = datetime.datetime.fromtimestamp(v)
                    dv[k] = pytz.utc.localize(dt)

        client = None
        # if the client already exists
        if dv.get('id'):
            client = self.model.objects.\
                        filter(pk=dv['id']).first()

        if dv.get('client_id'):
            client = self.model.objects.\
                        filter(client_id=dv['client_id']).first()

        if not client:
            client_id = dv.pop('client_id')
            client = self.model.objects.create(client_id=client_id)

        for k,v in dv.items():
            setattr(client, k, v)

        client.save()

    def __str__(self):
        return self.__dict__
