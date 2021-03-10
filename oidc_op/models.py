import datetime
import json

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from oidcop.utils import load_yaml_config


OIDC_OP_CONFIG = load_yaml_config(settings.OIDCENDPOINT_CONFIG)
OIDC_RESPONSE_TYPES = OIDC_OP_CONFIG['op']\
                        ['server_info']['endpoint']['authorization']\
                        ['kwargs']['response_types_supported']

OIDC_TOKEN_AUTHN_METHODS = OIDC_OP_CONFIG['op']\
                            ['server_info']['endpoint']['token']\
                            ['kwargs']['client_authn_method']

OIDC_GRANT_TYPES = OIDC_OP_CONFIG['op']\
                    ['server_info']['capabilities']['grant_types_supported']

TIMESTAMP_FIELDS = ['client_id_issued_at', 'client_secret_expires_at']

# configured in oidcendpoint
OIDC_OP_STATE_VALUE_LEN = 32 # it's not a fixed value, it depends by clients. Here it just references JWTConnect-Python-OidcRP
OIDC_OP_SID_VALUE_LEN = 56
OIDC_OP_SUB_VALUE_LEN = 64


# TODO: these test should be improved once oidcendpoint will have specialized objects as values instead of simple strings
def is_state(value):
    # USELESS: state is always generated by client/RP!
    return len(value) == OIDC_OP_STATE_VALUE_LEN

def is_sid(value):
    return len(value) == OIDC_OP_SID_VALUE_LEN

def is_sub(value):
    return len(value) == OIDC_OP_SUB_VALUE_LEN

def is_code(value):
    # Z0FBQUFBQmZEc1Z5Z1dMRVptX1J6d3AwTDVMdkVtbU1Rcm41VkVVbm03N3pwY21qYlpXc1M0ME1TU25fVlZMdm9MVnFKSW1zb3E4TW1aS0MzeVk4OWF2VjYtZ3FmZ0FXQkluUnVuSEJyWFhtcDFhOEdpTnFiVTdJME1qTFZoWWM2X3lQaGY0VGI0QWZNVUNJc3p6RnRMMWlOUUZzc0gtV3BsdVJvcTBIR3hsbk5SSmV1NVJ0M1N0UXcwV3JLeUR3N1NHYU54U21XVEFpYnBCSnBjN0dYeXFETVByT0J3YnZTSmlqblZSb3JXQmtuazFYdkU3cnNMaz0=
    return len(value) > 256


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

    unique if available (check on save):
        client_secret should be
        registration_access_token unique if available

    issued -> number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time
    client_salt -> must be autogenerated on save
    """
    _TOKEN_AUTH_CHOICES = ((i, i) for i in OIDC_TOKEN_AUTHN_METHODS)

    client_id = models.CharField(max_length=255,
                                 blank=False, null=False, unique=True)
    client_salt = models.CharField(max_length=255, blank=True, null=True)
    registration_access_token = models.CharField(max_length=255,
                                                 blank=True,
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
                                        null=True, default='web')
    token_endpoint_auth_method = models.CharField(choices=_TOKEN_AUTH_CHOICES,
                                                  max_length=33,
                                                  blank=True, null=True,
                                                  default="client_secret_basic")
    jwks_uri = models.URLField(max_length=255, blank=True, null=True)
    post_logout_redirect_uris = models.CharField(max_length=254,
                                                 blank=True, null=True)
    redirect_uris = models.CharField(max_length=254,
                                     blank=True, null=True)
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
        old = self.oidcrpgranttype_set.filter(client = self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            self.oidcrpgranttype_set.create(client=self,
                                            grant_type=value)

    @property
    def response_types(self):
        return [elem.response_type
                for elem in
                self.oidcrpresponsetype_set.filter(client=self)]

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
        for elem in self.oidcrpredirecturi_set.\
          filter(client = self, type='post_logout_redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @post_logout_redirect_uris.setter
    def post_logout_redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client = self)
        old.delete()
        for value in values:
            args = json.dumps(value[1] if value[1] else [])
            self.oidcrpredirecturi_set.create(client=self,
                                              uri=value[0],
                                              values=args,
                                              type='post_logout_redirect_uris')

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
                                              type='redirect_uris')

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
    response_type = models.CharField(choices=[(i,i) for i in OIDC_RESPONSE_TYPES],
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
    grant_type = models.CharField(choices=[(i,i)
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


class OidcSessionSso(TimeStampedModel):
    """
    """

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE,
                             blank=True, null=True)
    sub = models.CharField(max_length=255,
                           blank=True, null=True)

    class Meta:
        verbose_name = ('SSO Session SSO')
        verbose_name_plural = ('SSO Sessions SSO')

    def get_session(self):
        return OidcSession.objects.filter(sso=self).first()

    @property
    def state(self):
        session = self.get_session()
        if session:
            return session.state or ''
        return ''

    @property
    def username(self):
        if self.user:
            return self.user.username or ''
        return ''

    def __iter__(self):
        session = self.get_session()
        yield session.sid

    def __contains__(self, k):
        if getattr(self, k, None):
            return True
        else:
            return False

    def __delitem__(self, name):
        OidcSession.objects.filter(sso=self).delete()
        self.delete()

    def __getitem__(self, name):
        if is_sid(name):
            if OidcSession.objects.filter(sid=name, sso=self):
                return self
        elif name == 'sid':
            return self.sid
        else:
            if OidcSession.objects.filter(state=name, sso=self):
                return self
            return getattr(self, name)

    def get(self, name, default=None):
        return self.__getattribute__(name)

    def __getattribute__(self, name):
        if name == 'state':
            return self
        elif name == 'uid':
            return self.user.username
        elif name == 'sid':
            return self
        else:
            return models.Model.__getattribute__(self, name)

    def __setattribute__(self, name, value):
        if name == 'state':
            self.sid = value
            return
        elif name == 'uid':
            user = get_user_model().objects.filter(username=value[0]).first()
            self.user = user
            self.save()
            return
        elif name == 'sub':
            self.sub = value[0]
            self.save()
        else:
            return models.Model.__setattribute__(self, name, value)

    def __setitem__(self, key, value):
        return self.__setattribute__(key, value)

    def append(self, value):
        """multiple sid to a sso
        """
        if is_sid(value):
            if not isinstance(value, list):
                value = [value]

            session = self.get_session()
            session.sid = value[0] if isinstance(value, list) else value
            session.save()
        else:
            #  import pdb; pdb.set_trace()
            _msg =  '{} .append({}) with missing handler!'
            logger.warn(_msg.format(self.__class__.name, value))


    def __str__(self):
        return 'user: {} - sub: {}'.format(self.username,
                                           self.sub)


class OidcSession(TimeStampedModel):
    """
    Store the session information in this model
    """
    state = models.CharField(max_length=255,
                             blank=False, null=False)
    sso = models.ForeignKey(OidcSessionSso, on_delete=models.CASCADE,
                            blank=True, null=True)
    code = models.CharField(max_length=1024,
                            blank=True, null=True)
    sid = models.CharField(max_length=255,
                           blank=True, null=True)
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE,
                               blank=True, null=True)
    session_info = models.TextField(blank=True, null=True)
    valid_until = models.DateTimeField(blank=True, null=True)


    class Meta:
        verbose_name = ('SSO Session')
        verbose_name_plural = ('SSO Sessions')


    @classmethod
    def get_by_sid(cls, value):
        sids = cls.objects.filter(sid=value,
                                  valid_until__gt=timezone.localtime())
        if sids:
            return sids.last()

    def copy(self):
        return dict(sid = self.sid or [],
                    state = self.state or '',
                    session_info = self.session_info)

    def append(self, value):
        """Not used, only back compatibility
        """
        pass

    def __iter__(self):
        for i in (self.sid,):
            yield i

    def __str__(self):
        return 'state: {}'.format(self.state or '')
