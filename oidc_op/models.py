import datetime
import json
import pytz

from django.conf import settings
from django.db import models
from oidcendpoint.sso_db import SSODb

from . configure import Configuration

_op_config = Configuration.create_from_config_file(settings.OIDCENDPOINT_CONFIG)

OIDC_RESPONSE_TYPES = _op_config.conf['op']\
                        ['server_info']['endpoint']['authorization']\
                        ['kwargs']['response_types_supported']

OIDC_TOKEN_AUTHN_METHODS = _op_config.conf['op']\
                            ['server_info']['endpoint']['token']\
                            ['kwargs']['client_authn_method']

OIDC_GRANT_TYPES = _op_config.conf['op']\
                    ['server_info']['capabilities']['grant_types_supported']

TIMESTAMP_FIELDS = ['client_id_issued_at', 'client_secret_expires_at']


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created`` and ``modified`` fields.
    """
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class OidcRelyingParty(TimeStampedModel):
    """
    See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

    endpoint.endpoint_context.cdb['gE6Yw35JFTl1']
    should return this asset

    # Client db
    {'gE6Yw35JFTl1':
        {'client_id': 'gE6Yw35JFTl1',
         'client_salt': '6flfsj0Z',
         'registration_access_token': 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY',
         'registration_client_uri': 'https://127.0.0.1:8000/registration_api?client_id=gE6Yw35JFTl1',
         'client_id_issued_at': 1575460012,
         'client_secret': '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1',
         'client_secret_expires_at': 1575892012,
         'application_type': 'web',
         'response_types': ['code'],
         'contacts': ['ops@example.com'],
         'token_endpoint_auth_method': 'client_secret_basic',
         'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
         'post_logout_redirect_uris': [('https://127.0.0.1:8099', None)],
         'grant_types': ['authorization_code'],
         'redirect_uris': [('https://127.0.0.1:8099/authz_cb/django_oidc_op', {})]
         }
    }


    unique if available (check on save):
        client_secret should be
        registration_access_token unique if available

    issued -> number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time
    client_salt -> must be autogenerated on save
    """
    client_id = models.CharField(max_length=255,
                                 blank=False, null=False, unique=True)
    client_salt = models.CharField(max_length=255, blank=True, null=True)
    registration_access_token = models.CharField(max_length=255, blank=True,
                                                 null=True)
    registration_client_uri = models.URLField(max_length=255,
                                              blank=True, null=True)
    client_id_issued_at = models.DateTimeField(blank=True, null=True)
    client_secret = models.CharField(max_length=255,
                                     blank=True, null=True,
                                     help_text=('It is not needed for Clients '
                                                'selecting a token_endpoint_auth_method '
                                                'of private_key_jwt'))
    client_secret_expires_at = models.DateTimeField(blank=True, null=True,
                                help_text=('REQUIRED if client_secret is issued'))
    application_type = models.CharField(max_length=255, blank=True,
                                        null=True)
    token_endpoint_auth_method = models.CharField(choices=[(i, i)
                                                           for i in
                                                           OIDC_TOKEN_AUTHN_METHODS],
                                                  max_length=33,
                                                  blank=True, null=True)
    jwks_uri = models.URLField(max_length=255, blank=True, null=True)
    post_logout_redirect_uris = models.CharField(max_length=254,
                                                 blank=True, null=True)
    redirect_uris = models.CharField(max_length=254,
                                     blank=True, null=True)
    is_active = models.BooleanField(('active'), default=True)
    last_seen = models.DateTimeField(blank=True, null=True)

    @property
    def grant_types(self):
        l = []
        for elem in self.oidcrpgranttype_set.filter(client = self):
            l.append(elem.grant_type)
        return l

    @grant_types.setter
    def grant_types(self, values):
        old = self.oidcrpgranttype_set.filter(client = self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpgranttype_set.create(client=self,
                                            grant_type=value)

    @property
    def response_types(self):
        l = []
        for elem in self.oidcrpresponsetype_set.filter(client = self):
            l.append(elem.response_type)
        return l

    @response_types.setter
    def response_types(self, values):
        old = self.oidcrpresponsetype_set.filter(client = self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpresponsetype_set.create(client=self,
                                               response_type=value)

    @property
    def post_logout_redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.filter(client = self,
                                                      type='post_logout_redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @post_logout_redirect_uris.setter
    def post_logout_redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client = self)
        old.delete()
        for value in values:
            self.oidcrpredirecturi_set.create(client=self,
                                              uri=value[0],
                                              values=json.dumps(value[1]),
                                              type='post_logout_redirect_uris'
                                              )

    @property
    def redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.filter(client = self,
                                                      type='redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @redirect_uris.setter
    def redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client = self)
        old.delete()
        for value in values:
            self.oidcrpredirecturi_set.create(client=self,
                                              uri=value[0],
                                              values=json.dumps(value[1]),
                                              type='redirect_uris'
                                              )

    class Meta:
        verbose_name = ('Relying Party')
        verbose_name_plural = ('Relying Parties')

    def copy(self):
        """
            Compability with rohe approach based on dictionaries
        """
        d = {k:v for k,v in self.__dict__.items() if k[0] != '_'}
        disabled = ('created', 'modified', 'is_active', 'last_seen')
        for dis in disabled:
            d.pop(dis)
        for key in TIMESTAMP_FIELDS:
            if key in d:
                d[key] = int(datetime.datetime.timestamp(d[key]))

        d['grant_types'] = self.grant_types
        d['response_types'] = self.response_types
        d['post_logout_redirect_uris'] = self.post_logout_redirect_uris
        d['redirect_uris'] = self.redirect_uris

        return d

    def __getitem__(self, key):
        """self[key]    Accessing an item using an index"""
        value = getattr(self, key)
        if key in TIMESTAMP_FIELDS:
            value = self.get_timestamp(key)
        return value

    def __setitem__(self, key, val):
        """ self[key] = val Assigning to an item using an index"""
        if key in TIMESTAMP_FIELDS:
            value = self.set_timestamp(key, val)
        else:
            setattr(self, key, val)
            self.save()

    def get_timestamp(self, key):
        value = getattr(self, key)
        return int(datetime.datetime.timestamp(value))

    def set_timestamp(self, key, value):
        ts = pytz.utc.localize(datetime.datetime.fromtimestamp(value))
        setattr(self, key, ts)
        self.save()

    def __str__(self):
        return '{}, [{}]'.format(self.client_id, self.is_active)


class OidcRPResponseType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    response_type = models.CharField(choices=[(i,i) for i in OIDC_RESPONSE_TYPES],
                                     max_length=60)
    class Meta:
        verbose_name = ('Relying Party Response Type')
        verbose_name_plural = ('Relying Parties Response Types')
        unique_together = ('client', 'response_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.grant_type)


class OidcRPGrantType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    grant_type = models.CharField(choices=[(i,i) for i in OIDC_GRANT_TYPES],
                                  max_length=60)
    class Meta:
        verbose_name = ('Relying Party GrantType')
        verbose_name_plural = ('Relying Parties GrantTypes')
        unique_together = ('client', 'grant_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.grant_type)


class OidcRPContact(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    contact = models.CharField(max_length=254,
                               blank=True, null=True,)
    class Meta:
        verbose_name = ('Relying Party Contact')
        verbose_name_plural = ('Relying Parties Contacts')
        unique_together = ('client', 'contact')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.contact)


class OidcRPRedirectUri(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    uri = models.CharField(max_length=254,
                           blank=True, null=True,)
    values = models.CharField(max_length=254,
                           blank=True, null=True,)
    type = models.CharField(choices=(('redirect_uris', 'redirect_uris'),
                                     ('post_logout_redirect_uris', 'post_logout_redirect_uris')),
                            max_length=33)
    class Meta:
        verbose_name = ('Relying Party URI')
        verbose_name_plural = ('Relying Parties URIs')

    def __str__(self):
        return '{} [{}] {}'.format(self.client,
                                   self.uri,
                                   self.type)


class OidcEndpointSSOdb(TimeStampedModel, SSODb):
    """
    SSODb is
    sso_db._db.db.items()

    [('__sid2uid__2b84eccdcd4b077e074c72bdc540625063fac770d1176789afc07647', ['wert']),
     ('__uid2sid__wert', ['2b84eccdcd4b077e074c72bdc540625063fac770d1176789afc07647']),
     ('__sid2sub__2b84eccdcd4b077e074c72bdc540625063fac770d1176789afc07647', ['80327042b96b9f1c00d9d04db816e84af4e3616db1d0694b13ab86f49fd251bf']),
     ('__sub2sid__80327042b96b9f1c00d9d04db816e84af4e3616db1d0694b13ab86f49fd251bf', ['2b84eccdcd4b077e074c72bdc540625063fac770d1176789afc07647'])
     ]
    """

    # TO BE IMPLEMENTED OR NOT [WiP]
    pass
