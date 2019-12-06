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
        if session_key:
            self.session_key = init_key(**session_key)
            # self.op['server_info']['password'] = self.session_key
            self.logger.debug("Set server password to %s", self.session_key.key)

        # TODO: automagic cookie jwk builder
        # cookie_dealer = self.op['server_info'].get('cookie_dealer')
        # if cookie_dealer:
            # ## sign_jwk
            # cookie_sign_jwk = cookie_dealer.get('kwargs', {}).get('sign_jwk')
            # if cookie_sign_jwk:
                # self.cookie_sign_jwk = init_key(**cookie_sign_jwk)
                # self.logger.debug("Set cookie_sign_jwk to %s",
                                  # self.cookie_sign_jwk)
            # ## enc_jwk
            # cookie_enc_jwk = cookie_dealer['kwargs'].get('enc_jwk')
            # if cookie_enc_jwk:
                # self.cookie_enc_jwk = init_key(**cookie_enc_jwk)
                # self.logger.debug("Set cookie_enc_jwk to %s",
                                  # self.cookie_enc_jwk)

        # set OP session key
        if self.op :
            if self.op['server_info'].get('password') is None:
                key = self.session_key.key
                self.op['server_info']['password'] = key
                self.logger.debug("Set server password to %s", key)

        # templates environment
        self.template_dir = os.path.abspath(conf.get('template_dir', 'templates'))


    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
