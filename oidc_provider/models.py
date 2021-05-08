import datetime
import json

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from oidcop.utils import load_yaml_config


OIDC_RESPONSE_TYPES = settings.OIDCOP_CONFIG['op']['server_info'][
    'endpoint']['authorization']['kwargs']['response_types_supported']

OIDC_TOKEN_AUTHN_METHODS = settings.OIDCOP_CONFIG['op']['server_info'][
    'endpoint']['token']['kwargs']['client_authn_method']

OIDC_GRANT_TYPES = settings.OIDCOP_CONFIG['op']['server_info']['capabilities']['grant_types_supported']

TIMESTAMP_FIELDS = ['client_id_issued_at', 'client_secret_expires_at']


def get_client_by_id(client_id):
    client = OidcRelyingParty.objects.filter(
                            client_id = client_id,
                            is_active = True

    )
    if client:
        return client.last()


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

    {
        'client_id': '86M1io6O2Vdy',
        'client_salt': 'ehXmVjYE',
        'registration_access_token': 'lRail9TKK3Cj4kZdSt3KDorKVxyQvVGL',
        'registration_client_uri': 'https://127.0.0.1:5000/registration_api?client_id=86M1io6O2Vdy',
        'client_id_issued_at': 1619384394,
        'client_secret': '9f9a5b6dc23daca606c3766a1c6a0de29a2009b007be3d1da7ff8ca5',
        'client_secret_expires_at': 1621976394,
        'application_type': 'web',
        'response_types': ['code'],
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        'post_logout_redirect_uris': [('https://127.0.0.1:8090/session_logout/local', '')],
        'jwks_uri': 'https://127.0.0.1:8090/static/jwks.json',
        'frontchannel_logout_uri': 'https://127.0.0.1:8090/fc_logout/local',
        'frontchannel_logout_session_required': True,
        'backchannel_logout_uri': 'https://127.0.0.1:8090/bc_logout/local',
        'grant_types': ['authorization_code'],
        'redirect_uris': [('https://127.0.0.1:8090/authz_cb/local', {})]
    }
    """
    _TOKEN_AUTH_CHOICES = ((i, i) for i in OIDC_TOKEN_AUTHN_METHODS)

    client_id = models.CharField(
        max_length=255, blank=False, null=False, unique=True
    )
    client_salt = models.CharField(
        max_length=255, blank=True, null=True
    )
    registration_access_token = models.CharField(
        max_length=255, blank=True, null=True
    )
    registration_client_uri = models.URLField(
        max_length=255, blank=True, null=True
    )
    client_id_issued_at = models.DateTimeField(blank=True, null=True)
    client_secret = models.CharField(
        max_length=255,
        blank=True, null=True,
        help_text=('It is not needed for Clients '
                   'selecting a token_endpoint_auth_method '
                   'of private_key_jwt')
    )
    client_secret_expires_at = models.DateTimeField(
        blank=True, null=True,
        help_text=('REQUIRED if client_secret is issued')
    )
    application_type = models.CharField(
        max_length=255, blank=True,
        null=True, default='web'
    )
    token_endpoint_auth_method = models.CharField(
        choices=_TOKEN_AUTH_CHOICES,
        max_length=33,
        blank=True, null=True,
        default="client_secret_basic"
    )
    jwks_uri = models.URLField(max_length=255, blank=True, null=True)
    post_logout_redirect_uris = models.CharField(
        max_length=254, blank=True, null=True
    )
    redirect_uris = models.CharField(
        max_length=254, blank=True, null=True
    )
    is_active = models.BooleanField(('active'), default=True)
    last_seen = models.DateTimeField(blank=True, null=True)

    @property
    def allowed_scopes(self):
        scopes = self.oidcrpscope_set.filter(client=self)
        if scopes:
            return [i.scope for i in scopes]
        else:
            return ['openid']

    @allowed_scopes.setter
    def allowed_scopes(self, values):
        for i in values:
            scope = self.oidcrpscope_set.create(client=self, scope=i)

    @property
    def contacts(self):
        return [elem.contact
                for elem in self.oidcrpcontact_set.filter(client=self)]

    @contacts.setter
    def contacts(self, values):
        old = self.oidcrpcontact_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpcontact_set.create(client=self,
                                          contact=value)

    @property
    def grant_types(self):
        return [elem.grant_type
                for elem in
                self.oidcrpgranttype_set.filter(client=self)]

    @grant_types.setter
    def grant_types(self, values):
        old = self.oidcrpgranttype_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpgranttype_set.create(client=self,
                                            grant_type=value)

    @property
    def response_types(self):
        return [
            elem.response_type
            for elem in
            self.oidcrpresponsetype_set.filter(client=self)
        ]

    @response_types.setter
    def response_types(self, values):
        old = self.oidcrpresponsetype_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpresponsetype_set.create(
                client=self, response_type=value
            )

    @property
    def post_logout_redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.\
                filter(client=self, type='post_logout_redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @post_logout_redirect_uris.setter
    def post_logout_redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client=self)
        old.delete()
        for value in values:
            args = json.dumps(value[1] if value[1] else [])
            self.oidcrpredirecturi_set.create(
                client=self,
                uri=value[0],
                values=args,
                type='post_logout_redirect_uris'
            )

    @property
    def redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.filter(
                client=self, type='redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @redirect_uris.setter
    def redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client=self)
        old.delete()
        for value in values:
            self.oidcrpredirecturi_set.create(client=self,
                                              uri=value[0],
                                              values=json.dumps(value[1]),
                                              type='redirect_uris')

    class Meta:
        verbose_name = ('Relying Party')
        verbose_name_plural = ('Relying Parties')

    def copy(self):
        """
            Compability with rohe approach based on dictionaries
        """
        d = {k: v for k, v in self.__dict__.items() if k[0] != '_'}
        disabled = ('created', 'modified', 'is_active', 'last_seen')
        for dis in disabled:
            d.pop(dis)
        for key in TIMESTAMP_FIELDS:
            if d.get(key):
                d[key] = int(datetime.datetime.timestamp(d[key]))

        d['contacts'] = self.contacts
        d['grant_types'] = self.grant_types
        d['response_types'] = self.response_types
        d['post_logout_redirect_uris'] = self.post_logout_redirect_uris
        d['redirect_uris'] = self.redirect_uris
        d['allowed_scopes'] = self.allowed_scopes
        return d

    def __str__(self):
        return '{}'.format(self.client_id)


class OidcRPResponseType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    response_type = models.CharField(choices=[(i, i) for i in OIDC_RESPONSE_TYPES],
                                     max_length=60)

    class Meta:
        verbose_name = ('Relying Party Response Type')
        verbose_name_plural = ('Relying Parties Response Types')
        unique_together = ('client', 'response_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.response_type)


class OidcRPGrantType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    grant_type = models.CharField(choices=[(i, i)
                                           for i in OIDC_GRANT_TYPES],
                                  max_length=60)

    class Meta:
        verbose_name = ('Relying Party GrantType')
        verbose_name_plural = ('Relying Parties GrantTypes')
        unique_together = ('client', 'grant_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.grant_type)


class OidcRPContact(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    contact = models.CharField(max_length=254,
                               blank=True, null=True,)

    class Meta:
        verbose_name = ('Relying Party Contact')
        verbose_name_plural = ('Relying Parties Contacts')
        unique_together = ('client', 'contact')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.contact)


class OidcRPRedirectUri(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    uri = models.CharField(max_length=254,
                           blank=True, null=True)
    values = models.CharField(max_length=254,
                              blank=True, null=True)
    type = models.CharField(choices=(('redirect_uris', 'redirect_uris'),
                                     ('post_logout_redirect_uris',
                                      'post_logout_redirect_uris')),
                            max_length=33)

    class Meta:
        verbose_name = ('Relying Party URI')
        verbose_name_plural = ('Relying Parties URIs')

    def __str__(self):
        return '{} [{}] {}'.format(self.client, self.uri, self.type)


class OidcRPScope(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    scope = models.CharField(max_length=254,
                             blank=True, null=True,)

    class Meta:
        verbose_name = ('Relying Party Scope')
        verbose_name_plural = ('Relying Parties Scopes')
        unique_together = ('client', 'scope')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.scope)


class OidcIssuedToken(TimeStampedModel):
    """
        {
            "type": "authorization_code",
            "issued_at": 1605452123,
            "not_before": 0,
            "expires_at": 1605452423,
            "revoked": false,
            "value": "Z0FBQUFBQmZzVUZieDFWZy1fbjE2ckxvZkFTVC1ZTHJIVlk0Z09tOVk1M0RsOVNDbkdfLTIxTUhILWs4T29kM1lmV015UEN1UGxrWkxLTkVXOEg1WVJLNjh3MGlhMVdSRWhYcUY4cGdBQkJEbzJUWUQ3UGxTUWlJVDNFUHFlb29PWUFKcjNXeHdRM1hDYzRIZnFrYjhVZnIyTFhvZ2Y0NUhjR1VBdzE0STVEWmJ3WkttTk1OYXQtTHNtdHJwYk1nWnl3MUJqSkdWZGFtdVNfY21VNXQxY3VzalpIczBWbGFueVk0TVZ2N2d2d0hVWTF4WG56TDJ6bz0=",
            "usage_rules": {
                "expires_in": 300,
                "supports_minting": [
                    "access_token",
                    "refresh_token",
                    "id_token"
                ],
                "max_usage": 1
                },
            "used": 0,
            "based_on": null,
            "id": "96d19bea275211eba43bacde48001122"
       },
    """
    TT_CHOICES = (
        ('authorization_code', 'authorization_code'),
        ('access_token','access_token'),
        ('id_token', 'id_token'),
    )

    id = models.CharField(max_length=128, blank=True, null=True)
    type = models.CharField(choices = TT_CHOICES,
                            max_length=32,
                            blank=False, null=False)

    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    not_before = models.DateTimeField(blank=True, null=True)

    revoked = models.BooleanField(default=False)
    value = models.TextField()

    usage_rules = models.TextField()
    used = models.IntegerField(default=0)
    based_on = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = ('OIDC Issued Token')
        verbose_name_plural = ('OIDC Issued Tokens')

    def __str__(self):
        return f'{self.id} [{self.type}]'


class OidcGrants(TimeStampedModel):
    """
    Store the session information in this model
    """

    user_uid = models.CharField(max_length=120,
                           blank=False, null=False)

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE,
                             blank=True, null=True)
    sub = models.CharField(max_length=255,
                           blank=True, null=True)

    state = models.CharField(max_length=255,
                             blank=True, null=True)
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE,
                               blank=True, null=True)
    session_info = models.TextField(blank=True, null=True)

    grant = models.TextField(blank=True, null=True)
    grant_id = models.CharField(max_length=255,
                                blank=True, null=True)

    issued_at = models.DateTimeField(blank=True, null=True)
    valid_until = models.DateTimeField(blank=True, null=True)

    code = models.CharField(max_length=1024,
                            blank=True, null=True)
    sid = models.CharField(max_length=255,
                           blank=True, null=True)
    sub = models.CharField(max_length=255,
                           blank=True, null=True)

    class Meta:
        verbose_name = ('SSO Session')
        verbose_name_plural = ('SSO Sessions')


    @classmethod
    def create_by(cls, **data):

        if data.get('client_id'):
            client = get_client_by_id(data['client_id'])
            data['client'] = client
            data.pop('client_id')

        if data.get('session_info'):
            data['session_info'] = json.dumps(data['session_info'].__dict__)

        res = cls.objects.create(**data)
        return res


    @classmethod
    def get_by_sid(cls, value):
        sids = cls.objects.filter(sid=value,
                                  valid_until__gt=timezone.localtime())
        if sids:
            return sids.last()


    @classmethod
    def get_session_by(cls, **data):

        if data.get('client_id'):
            client = get_client_by_id(data['client_id'])
            data.pop('client_id')
            data['client'] = client



        data['valid_until__gt'] = timezone.localtime()
        res = cls.objects.filter(**data)
        if res:
            return res.last()


    @classmethod
    def get_by_client_id(self, uid):
        res = cls.objects.filter(uid=value,
                                 valid_until__gt=timezone.localtime())
        if res:
            return self.session_info


    def set_grant(self, grant):
        """
        {'issued_at': 1615403213, 'not_before': 0, 'expires_at': 0,
         'revoked': False, 'used': 0, 'usage_rules': {}, 'scope': [],
         'authorization_details': None,
         'authorization_request': <oidcmsg.oidc.AuthorizationRequest object at 0x7fa73521efa0>,
         'authentication_event': <oidcop.authn_event.AuthnEvent object at 0x7fa735223070>,
         'claims': {}, 'resources': [], 'issued_token': [],
         'id': 'c695a5e881d311eb905343ee297b1c98',
         'sub': '204176ab8fe8917ee4788683bcee4ebc04bfe1ab659485ec61b2b2b4108c5272',
         'token_map': {
            'authorization_code': <class 'oidcop.session.token.AuthorizationCode'>,
            'access_token': <class 'oidcop.session.token.AccessToken'>,
            'refresh_token': <class 'oidcop.session.token.RefreshToken'>}
        }
        """
        self.issued_at = timezone.make_aware(timezone.datetime.fromtimestamp(grant.issued_at))
        self.sub = grant.sub
        self.grant_id = grant.id

        grant.authorization_request = grant.authorization_request.to_json()
        grant.authentication_event = grant.authentication_event.to_json()
        # breakpoint()
        # grant.token_map['authorization_code'] = grant.token_map['authorization_code'].to_json()
        # grant.token_map['access_token'] = grant.token_map['access_token'].to_json()
        # grant.token_map['refresh_token'] = grant.token_map['refresh_token'].to_json()
        grant.token_map.pop('authorization_code')
        grant.token_map.pop('access_token')
        grant.token_map.pop('refresh_token')

        self.grant = grant.to_json()
        self.save()
        return grant

    @classmethod
    def get_by_session_id(cls, user_uid, client_id, grant_id):
        grant = cls.objects.filter(user_uid = user_uid,
                                   client__client_id = client_id,
                                   grant_id = grant_id)
        if grant:
            return grant.last()



    def copy(self):
        return dict(sid=self.sid or [],
                    state=self.state or '',
                    session_info=self.session_info)


    def append(self, value):
        """Not used, only back compatibility
        """


    def __iter__(self):
        for i in (self.sid,):
            yield i


    def __str__(self):
        return 'state: {}'.format(self.state or '')
