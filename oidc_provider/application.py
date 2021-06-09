import logging
import os
import json

from django.conf import settings
from oidcop.server import Server

from urllib.parse import urlparse
from oidcop.configure import OPConfiguration

folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def init_oidc_op_endpoints(app):
    op_config = app.srv_config

    op_config['issuer']
    server = Server(op_config, cwd=folder)

    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        endp.vpath = _vpath

    return server


def oidc_provider_init_app(config, name='oidc_op', **kwargs):
    name = name or __name__
    app = type('OIDCAppEndpoint', (object,), {"srv_config": config})
    # Initialize the oidc_provider after views to be able to set correct urls
    app.endpoint_context = init_oidc_op_endpoints(app)
    return app


def oidcop_application(conf=None):
    conf = conf or settings.OIDCOP_CONFIG
    domain = getattr(settings, 'DOMAIN', None)
    port = getattr(settings, 'PORT', None)
    config = OPConfiguration(conf=conf['op']['server_info'],
                             domain=domain,
                             port=port)
    app = oidc_provider_init_app(config)
    os.environ['OIDCOP_CONFIG'] = json.dumps(conf)
    return app


oidcop_app = oidcop_application(conf=settings.OIDCOP_CONFIG)
