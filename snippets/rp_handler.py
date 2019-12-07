import os

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from oidcrp import RPHandler
from oidcrp.util import load_yaml_config



def init_oidc_rp_handler(app):
    rp_keys_conf = app.config.get('RP_KEYS')
    if rp_keys_conf is None:
        rp_keys_conf = app.config.get('OIDC_KEYS')

    verify_ssl = app.config.get('VERIFY_SSL')
    hash_seed = app.config.get('HASH_SEED')
    if not hash_seed:
        hash_seed = "BabyHoldOn"

    if rp_keys_conf:
        _kj = init_key_jar(**rp_keys_conf)
        _path = rp_keys_conf['public_path']
        if _path.startswith('./'):
            _path = _path[2:]
        elif _path.startswith('/'):
            _path = _path[1:]
    else:
        _kj = KeyJar()
        _path = ''
    _kj.verify_ssl = verify_ssl

    rph = RPHandler(base_url=app.config.get('BASEURL'), hash_seed=hash_seed,
                    keyjar=_kj, jwks_path=_path,
                    client_configs=app.config.get('CLIENTS'),
                    services=app.config.get('SERVICES'),
                    verify_ssl=verify_ssl)
    return rph


rph = RPHandler()
issuer_id = "django_oidc_op"
info = rph.begin(issuer_id)
print(info['url'])

rph.issuer2rp
# {'https://127.0.0.1:8000': <oidcrp.oidc.RP at 0x7f4dba8b0e10>}

rph.hash2issuer
# {'django_oidc_op': 'https://127.0.0.1:8000'}

rp = rph.issuer2rp['https://127.0.0.1:8000']

# provider info
rp.service_context.provider_info.to_dict()

# do dynamic client registration
rp.service_context.registration_response['client_id']

# authorization
au = rp.service_context.service['authorization']
req = au.construct_request()

# rp.service_context.provider_info['authorization_endpoint'] == au.endpoint
authz_url = req.request(location=au.endpoint)
resp = rp.http(authz_url)

# that's the login form
resp.text

# regexp per estrarre action url e token da resp.text

import requests
resp = requests.post('https://127.0.0.1:8000/verify/oidc_user_login/', data={'token':'eyJhbGciOiJSUzI1NiIsImtpZCI6Ilh6UnpNRTFhZUZWUVFscG5ieko1UmpGWmVrOUJWM0Z4UjJSc1VtWkZNM2R3YTAweU0wWkNNVlJ0T0EifQ.eyJhdXRobl9jbGFzc19yZWYiOiAib2lkY2VuZHBvaW50LnVzZXJfYXV0aG4uYXV0aG5fY29udGV4dC5JTlRFUk5FVFBST1RPQ09MUEFTU1dPUkQiLCAicXVlcnkiOiAic3RhdGU9eHY5a09XVUt4QVgwN2hZUkE3SmNGQkVhYVdMNktGbjkmcmVkaXJlY3RfdXJpPWh0dHBzJTNBJTJGJTJGMTI3LjAuMC4xJTNBODA5OSUyRmF1dGh6X2NiJTJGZGphbmdvX29pZGNfb3AmcmVzcG9uc2VfdHlwZT1jb2RlJnNjb3BlPW9wZW5pZCZub25jZT13RUkyanVtMFFEaVIzeWdIU0VJWjh4dmxQdm9UUTRYaCZjb2RlX2NoYWxsZW5nZT1xMzYyeWZNM0NRMk5VdEtycFpXTndSY2tubXB6OVA2OS1ZU1g3LWlXZFVJJmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JmNsaWVudF9pZD1Sa0E2THVVUEtCS0oiLCAicmV0dXJuX3VyaSI6ICJodHRwczovLzEyNy4wLjAuMTo4MDk5L2F1dGh6X2NiL2RqYW5nb19vaWRjX29wIiwgImlzcyI6ICJodHRwczovLzEyNy4wLjAuMTo4MDAwIiwgImlhdCI6IDE1NzU2ODcyOTF9.HDngQLZxsOYP88IIJdpH4f9EO6t50Wj_S7zHq973Wd9F2SUw8jpWF0S6JgWImWxLL7A_Tf1QKHYI4ZAvhH6VwRHtde1y0jtLgaihCxuvwX4fIxOLX0AHprmgfUrV3XjpS4JPBLcUwJU_gU1uL9LyGYz97UJGZL2xv0VewkEXBTjNjx6v7f-rpD0ZTb4YcoU_OwWGwh_lpH9-W292Szg0nRJjpg34bZASo9mNjBbzVuhMMcsYtqMDplWeM2cBijk7pGAGMtWnlGBPMDgUp6SMrYLJ8Zph5-Tm00mUxEhtnv0I0mzK0T2uDFSr4xTzZFtzb6jV1-3lZzMw03WTdHPTFQ', 'username':'wert', 'password':'myhack'}, verify=False)

/authz_cb/django_oidc_op?state=xv9kOWUKxAX07hYRA7JcFBEaaWL6KFn9&scope=openid&code=Z0FBQUFBQmQ2eFdrYVBUMFgxSVM3MXphbUlFSGltS1RZbjA3TldwQ0UyV0VoZkVvMmFzbnk0cnR3ZzZuYlYzV2tmOXVhMy1KMUVSZjhyWEFMZV8zNy1PLXJOX1JQd0xaM0dPd19DLWRYVTlfcy1BTGVxemJ4YnhZNTFRRldCM3c2TG5nd2kxLVF5WW5aeWNzdVk4M3IzZ19lb25icmFnNkQ4Skl2bzlOcmZ2OVRocjZhR0dHM3p0a0lpZWM4dDc4aDVDT2dDMkdvMWRYMGVsV1hQVzB0cFdNaVpJamE3aW0xeTk4NFNwT2g2cVBYeEExRjh6bzZiST0%3D&session_state=2a41dcc2d5404b4cce554fef8a79f0fc68e9b2928d73094851a9f546453f92e0.s0ooM37zNYnSkaND&iss=https%3A%2F%2F127.0.0.1%3A8000&client_id=RkA6LuUPKBKJ

urllib.parse.parse_qs('state=xv9kOWUKxAX07hYRA7JcFBEaaWL6KFn9&scope=openid&code=Z0FBQUFBQmQ2eFdrYVBUMFgxSVM3MXphbUlFSGltS1RZbjA3TldwQ0UyV0VoZkVvMmFzbnk0cnR3ZzZuYlYzV2tmOXVhMy1KMUVSZjhyWEFMZV8zNy1PLXJOX1JQd0xaM0dPd19DLWRYVTlfcy1BTGVxemJ4YnhZNTFRRldCM3c2TG5nd2kxLVF5WW5aeWNzdVk4M3IzZ19lb25icmFnNkQ4Skl2bzlOcmZ2OVRocjZhR0dHM3p0a0lpZWM4dDc4aDVDT2dDMkdvMWRYMGVsV1hQVzB0cFdNaVpJamE3aW0xeTk4NFNwT2g2cVBYeEExRjh6bzZiST0%3D&session_state=2a41dcc2d5404b4cce554fef8a79f0fc68e9b2928d73094851a9f546453f92e0.s0ooM37zNYnSkaND&iss=https%3A%2F%2F127.0.0.1%3A8000&client_id=RkA6LuUPKBKJ')

atr = ac.construct_request(**{'state': 'xv9kOWUKxAX07hYRA7JcFBEaaWL6KFn9',
 'scope': 'openid',
 'code': 'Z0FBQUFBQmQ2eFdrYVBUMFgxSVM3MXphbUlFSGltS1RZbjA3TldwQ0UyV0VoZkVvMmFzbnk0cnR3ZzZuYlYzV2tmOXVhMy1KMUVSZjhyWEFMZV8zNy1PLXJOX1JQd0xaM0dPd19DLWRYVTlfcy1BTGVxemJ4YnhZNTFRRldCM3c2TG5nd2kxLVF5WW5aeWNzdVk4M3IzZ19lb25icmFnNkQ4Skl2bzlOcmZ2OVRocjZhR0dHM3p0a0lpZWM4dDc4aDVDT2dDMkdvMWRYMGVsV1hQVzB0cFdNaVpJamE3aW0xeTk4NFNwT2g2cVBYeEExRjh6bzZiST0=',
 'session_state': '2a41dcc2d5404b4cce554fef8a79f0fc68e9b2928d73094851a9f546453f92e0.s0ooM37zNYnSkaND',
 'iss': 'https://127.0.0.1:8000',
 'client_id': 'RkA6LuUPKBKJ'})



ac = rp.service_context.service['accesstoken']
