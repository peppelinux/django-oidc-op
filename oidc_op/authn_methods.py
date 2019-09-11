# import django
from django.template.loader import render_to_string

from oidcendpoint.util import instantiate
from oidcendpoint.user_authn.user import (create_signed_jwt,
                                          verify_signed_jwt)
from oidcendpoint.user_authn.user import UserAuthnMethod


class UserPassDjango(UserAuthnMethod):
    """
    see oidcendpoint.authn_context
        oidcendpoint.endpoint_context

        https://docs.djangoproject.com/en/2.2/ref/templates/api/#rendering-a-context
    """

    # TODO: get this though settings conf
    url_endpoint = "/verify/user_pass_django"

    def __init__(self, db, template_handler=render_to_string, template="oidc_login.html",
                 endpoint_context=None, verify_endpoint='', **kwargs):
        """
        template_handler is only for backwards compatibility, it will be always replaced by Django's default
        """

        super(UserPassDjango, self).__init__(endpoint_context=endpoint_context)

        self.kwargs = kwargs
        self.kwargs.setdefault("page_header", "Log in")
        self.kwargs.setdefault("user_label", "Username")
        self.kwargs.setdefault("passwd_label", "Password")
        self.kwargs.setdefault("submit_btn", "Log in")
        self.kwargs.setdefault("tos_uri", "")
        self.kwargs.setdefault("logo_uri", "")
        self.kwargs.setdefault("policy_uri", "")
        self.kwargs.setdefault("tos_label", "")
        self.kwargs.setdefault("logo_label", "")
        self.kwargs.setdefault("policy_label", "")

        # TODO check this
        self.template_handler = render_to_string
        self.template = template

        # TODO: force to Django....
        self.user_db = instantiate(db["class"], **db["kwargs"])

        self.action = verify_endpoint or self.url_endpoint
        self.kwargs['action'] = self.action


    def __call__(self, **kwargs):
        _ec = self.endpoint_context
        # Stores information need afterwards in a signed JWT that then
        # appears as a hidden input in the form
        jws = create_signed_jwt(_ec.issuer, _ec.keyjar, **kwargs)

        self.kwargs['token'] = jws

        _kwargs = self.kwargs.copy()
        for attr in ['policy', 'tos', 'logo']:
            _uri = '{}_uri'.format(attr)
            try:
                _kwargs[_uri] = kwargs[_uri]
            except KeyError:
                pass
            else:
                _label = '{}_label'.format(attr)
                _kwargs[_label] = LABELS[_uri]

        # TODO: clean this
        # return self.template_handler.render(self.template, action=self.action,
                                            # token=jws, **_kwargs)

        #return self.template_handler.render(django.template.Context(_kwargs))
        return self.template_handler(self.template, _kwargs)

    def verify(self, *args, **kwargs):
        username = kwargs["username"]
        if username in self.user_db and self.user_db[username] == kwargs[
                "password"]:
            return username
        else:
            raise FailedAuthentication()
