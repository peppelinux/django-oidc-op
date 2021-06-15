import logging
import os
import re
import requests
import subprocess
import urllib
import urllib3
import time

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from oidcmsg.message import Message
from oidcrp import rp_handler
from oidcrp.util import load_yaml_config

from django.test import TestCase


logger = logging.getLogger('oidc_provider')
urllib3.disable_warnings()
RPHandler = rp_handler.RPHandler


def decode_token(bearer_token, keyjar, verify_sign=True):
    msg = Message().from_jwt(bearer_token,
                             keyjar=keyjar,
                             verify=verify_sign)
    return msg.to_dict()


def init_oidc_rp_handler(app):
    _rp_conf = app.config

    if _rp_conf.get('rp_keys'):
        _kj = init_key_jar(**_rp_conf['rp_keys'])
        _path = _rp_conf['rp_keys']['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf['httpc_params']
    hash_seed = app.config.get('hash_seed', "BabyHoldOn")
    rph = RPHandler(_rp_conf['base_url'], _rp_conf['clients'], services=_rp_conf['services'],
                    hash_seed=hash_seed, keyjar=_kj, jwks_path=_path,
                    httpc_params=_rp_conf['httpc_params'])
    return rph


def get_rph(config_fname):
    config = load_yaml_config(config_fname)
    app = type('RPApplication', (object,), {"config": config})
    rph = init_oidc_rp_handler(app)
    return rph


def run_rp_session(rph, issuer_id, username, password):
    # register client (provider info and client registration)
    info = rph.begin(issuer_id)
    issuer_fqdn = rph.hash2issuer[issuer_id]
    issuer_keyjar = rph.issuer2rp[issuer_fqdn]

    print(f'Request authz grant: {info["url"]}\n')
    res = requests.get(info['url'], verify=rph.verify_ssl)

    auth_code = re.search(
        'value="(?P<token>[a-zA-Z\-\.\_0-9]*)"',
        res.text).groupdict()['token']
    auth_url = re.search(
        'action="(?P<url>[a-zA-Z0-9\/\-\_\.\:]*)"',
        res.text).groupdict()['url']

    auth_dict = {
        'username': username,
        'password': password,
        'token': auth_code
    }

    auth_url = ''.join((issuer_fqdn, auth_url))
    req = requests.post(auth_url,
                        data=auth_dict, verify=rph.verify_ssl,
                        allow_redirects=False)

    print("Submitting credentails form:")
    print(auth_url, auth_dict, '\n')

    # req is a 302, a redirect to the https://127.0.0.1:8099/authz_cb/django_oidc_op
    if req.status_code != 302:
        raise Exception(req.content)
    rp_final_url = req.headers['Location']
    ws, args = urllib.parse.splitquery(rp_final_url)

    request_args = urllib.parse.parse_qs(args)
    # from list to str
    request_args = {k: v[0] for k, v in request_args.items()}

    # oidcrp.RPHandler.finalize() will parse the authorization response and depending on the configuration run the needed RP service
    result = rph.finalize(request_args['iss'], request_args)

    # Tha't the access token, the bearer used to access to userinfo endpoint
    #  result['token']
    print("Bearer Access Token", result['token'], '\n')

    # get the keyjar related to the issuer
    decoded_access_token = decode_token(
        result['token'],
        keyjar=issuer_keyjar.get_service_context().keyjar
    )
    print("Access Token", decoded_access_token)
    print("ID Token", result['id_token'].to_dict())

    # userinfo
    result['userinfo'].to_dict()
    print("Userinfo endpoint result:", result['userinfo'].to_dict())


class TestOidcRPIntegration(TestCase):
    def setUp(self):
        self.rph = get_rph('../oidc_rp/conf.json')

        self.rph.verify_ssl = self.rph.httpc_params['verify']
        if not self.rph.verify_ssl:
            urllib3.disable_warnings()

        # select the OP you want to, example: "django_oidc_op"
        self.issuer_id = 'django_provider'

    def _run_example_project(self):
        """This is a pure integration test made with JWTConnect-Python-OidcRP"""
        os.chdir('../example')
        self.oidc_srv = subprocess.Popen(
            ["bash", "run.sh"],
            # stdout=subprocess.PIPE,
            # stderr=subprocess.PIPE
        )
        time.sleep(2)

    def test_all(self):
        self._run_example_project()
        run_rp_session(self.rph, self.issuer_id, 'test', 'testami18')
        os.system(
            """ps ax | grep "wsgi-file example/wsgi.py" | awk -F' ' {'print $1'} | xargs echo | xargs kill -KILL"""
        )
