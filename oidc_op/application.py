import logging
import os

from cryptojwt.key_jar import init_key_jar
from django.conf import settings
from oidcendpoint.endpoint_context import (EndpointContext,
                                           get_token_handlers,
                                           )
from oidcendpoint.session import create_session_db
from oidcendpoint.sso_db import SSODb
from urllib.parse import urlparse

from . configure import Configuration


logger = logging.getLogger(__name__)


def init_oidc_op_endpoints(app):
    _config = app.srv_config.op
    _server_info_config = _config['server_info']

    _kj_args = {k:v for k,v in _server_info_config['jwks'].items()
                if k != 'uri_path'}
    _kj = init_key_jar(**_kj_args)
    iss = _server_info_config['issuer']

    # make sure I have a set of keys under my 'real' name
    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''), iss)
    _kj.verify_ssl = _config['server_info'].get('verify_ssl', False)

    # TODO, overcome the circularity dep os ec and session_db have each other
    endpoint_context = EndpointContext(_server_info_config,
                                       # session_db=session_db,
                                       keyjar=_kj,
                                       cwd=settings.BASE_DIR)

    # Work in progress
    # session db - TODO: adopt a pure django approach
    # also check ec._sub_func
    # th_args = get_token_handlers(_config)
    # session_db = create_session_db(
        # endpoint_context, th_args, db=None, sso_db=SSODb(), sub_func=self._sub_func
    # )
    # endpoint_context.session_db = session_db

    return endpoint_context


def oidc_provider_init_app(config, name='oidc_op', **kwargs):
    name = name or __name__
    app = type('OIDCAppEndpoint', (object,), {"srv_config": config})
    # Initialize the oidc_provider after views to be able to set correct urls
    app.endpoint_context = init_oidc_op_endpoints(app)
    return app


def oidcendpoint_application(config_file=settings.OIDCENDPOINT_CONFIG):
    config = Configuration.create_from_config_file(config_file)
    app = oidc_provider_init_app(config)
    return app
