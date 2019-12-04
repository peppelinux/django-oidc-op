import logging
import os

from cryptojwt.key_jar import init_key_jar
from django.conf import settings
from oidcendpoint.endpoint_context import (EndpointContext,
                                           get_token_handlers,
                                           )
from oidcendpoint.in_memory_db import InMemoryDataBase
from oidcendpoint.session import create_session_db
from oidcendpoint.sso_db import SSODb
from oidcendpoint.util import importer

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

    # set session, client and ssodb
    client_db = None
    if _config.get("client_db"):
        cdb_kwargs = _config["client_db"].get('kwargs', {})
        client_db = importer(_config["client_db"]['class'])(**cdb_kwargs)

    session_db = None
    if _config.get("session_db"):
        ses_kwargs = _config["session_db"].get('kwargs', {})
        session_db = importer(_config["session_db"]['class'])(**ses_kwargs)

    sso_db = None
    if _config.get("sso_db"):
        ssodb_kwargs = _config["sso_db"].get('kwargs', {})
        sso_db = importer(_config["sso_db"]['class'])(**ssodb_kwargs)

    # TODO, overcome the circularity dep os ec and session_db have each other
    endpoint_context = EndpointContext(_server_info_config,
                                       client_db={},
                                       session_db=session_db,
                                       sso_db=sso_db,
                                       keyjar=_kj,
                                       cwd=settings.BASE_DIR)

    # th_args = get_token_handlers(_server_info_config)
    # db = InMemoryDataBase()
    # endpoint_context.set_session_db(_server_info_config,
                                    # sso_db=sso_db,
                                    # db=InMemoryDataBase())

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
