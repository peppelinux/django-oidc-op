import importlib
import logging
import os

from cryptojwt.key_jar import init_key_jar
from django.conf import settings
from oidcendpoint import token_handler
from oidcendpoint.endpoint_context import (EndpointContext,
                                           get_token_handlers)
from oidcendpoint.util import importer

from urllib.parse import urlparse
from . configure import Configuration

logger = logging.getLogger(__name__)


def init_oidc_op_endpoints(app):
    _config = app.srv_config.op
    _server_info_config = _config['server_info']

    folder = os.path.dirname(os.path.realpath(__file__))
    #  import pdb; pdb.set_trace()
    endpoint_context = EndpointContext(_server_info_config, cwd=folder)
    for endp in endpoint_context.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

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
