"""Configuration management for IDP"""

import json
import logging
import os
import sys
from typing import Dict

from cryptojwt.key_bundle import init_key
from django.conf import settings

# from oidcop.logging import configure_logging
from oidcop.utils import load_yaml_config

# TODO: check this
try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcendpoint import rndstr as rnd_token


logger = logging.getLogger(__name__)


class Configuration:
    """OP Configuration"""

    def __init__(self, conf: Dict) -> None:
        self.logger = logger #configure_logging(settings.LOGGING)

        # OIDC provider configuration
        self.conf = conf
        self.op = conf.get('op')

        # TODO: here manage static clients without dyn registration enabled
        # self.oidc_clients = conf.get('oidc_clients', {})

        # session key
        self.session_jwk = conf.get('session_jwk')
        # set OP session key
        session_key = self.op['server_info'].get('session_key')
        if isinstance(session_key, dict):
            self.session_key = init_key(**session_key)
            # self.op['server_info']['password'] = self.session_key
            self.logger.debug("Set server password to %s", self.session_key.key)

        # templates environment
        self.template_dir = os.path.abspath(conf.get('template_dir', 'templates'))


    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
