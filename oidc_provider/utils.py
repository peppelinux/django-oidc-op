import datetime
import json
import pytz

from oidcmsg.message import Message
from cryptojwt.key_jar import KeyJar

from . application import oidcop_app


def dt2timestamp(value):
    return int(datetime.datetime.timestamp(value))


def timestamp2dt(value):
    pytz.utc.localize(datetime.datetime.fromtimestamp(value))


def aware_dt_from_timestamp(timestamp):
    dt = datetime.datetime.fromtimestamp(timestamp)
    return pytz.timezone("UTC").localize(dt, is_dst=None)


def decode_token(txt, attr_name='access_token', verify_sign=True):
    issuer = oidcop_app.srv_config['issuer']
    jwks_path = oidcop_app.srv_config.conf['keys']['private_path']
    jwks = json.loads(open(jwks_path).read())

    key_jar = KeyJar()
    key_jar.import_jwks(jwks, issuer=issuer)

    msg = Message().from_jwt(txt,
                             keyjar=key_jar,
                             verify=verify_sign)
    return msg
