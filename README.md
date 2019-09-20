# django-oidc-op
A Django implementation of an **OIDC Provider** built top of [Roland Hedberg's libraries](https://github.com/rohe/oidc-op).
If you are just going to build a standard OIDC Provider you only have to write the configuration file.

## Status
_Work in Progress_

Please wait for the first release tag before considering it ready to use.
See Issues section.

Before adopting this project in a production use you should consider if the following endpoint should be enabled:

- [Web Finger](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
- [dynamic discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
- [dynamic client registration](https://openid.net/specs/openid-connect-registration-1_0.html)

**TODO**: _document how to disable them and how to register RP via django admin backend._

#### Endpoints

Available resources are:

- webfinger
  - /.well-known/webfinger [to be tested]

- provider_info
  - /.well-known/openid-configuration [tested, working]

- registration
  - /registration [tested, working]

- authorization
  - /authorization [tested, working]
  - authentication, which type decide to support, default: login form.

- token
  - access/authorization token

- refresh_token
- userinfo
  - /userinfo [test, working: need work to handle some attribute release policy]

- end_session
  - logout


## Run the example demo

````
git clone https://github.com/peppelinux/django-oidc-op.git
cd django-oidc-op

pip install -r requirements.txt

cd example
./manage.py migrate
./manage.py createsuperuser
./manage.py collectstatic

gunicorn example.wsgi -b0.0.0.0:8000 --keyfile=./data/oidc_op/certs/key.pem --certfile=./data/oidc_op/certs/cert.pem --reload
````

## Configure OIDC endpoint

#### Django settings.py parameters

`OIDC_OP_AUTHN_SALT_SIZE`: Salt size in byte, default: 4 (Integer).

#### Signatures
These following files needed to be present in `data/oidc_op/private`.

1. session.json (JWK symmetric);
2. cookie_sign_jwk.json (JWK symmetric);
3. cookie_enc_jwk.json (JWK symmetric), optional, see `conf.yaml`.

To create them by hands comment out `'read_only': False'` in `conf.yaml`,
otherwise they will be created automatically on each run.

A JWK creation example would be:
````
jwkgen --kty SYM > data/oidc_op/private/cookie_enc_jwk.json
````

## General description

The example included in this project enables dynamic registration of RPs (you can even disable it).
Using an example RP like [JWTConnect-Python-OidcRP](https://github.com/openid/JWTConnect-Python-OidcRP)
and configuring in `CLIENTS` section to use django-oidc-op (see `example/data/oidc_rp/conf.django.yaml`),
we'll see the following flow happens:

1. /.well-known/openid-configuration
   RP get the Provider configuration, what declared in the configuration at `op.server_info`;
2. /registration
   RP registers in the Provider if
3. /authorization
   RP mades OIDC authorization
4. RP going to be redirected to login form page (see authn_methods.py)
5. user-agent posts form (user credentials) to `/verify/user_pass_django`
6. verify_user in django, on top of oidcendpoint_app.endpoint_context.authn_broker
7. RP request for an access token -> the response of the previous authentication is a HttpRedirect to op's /token resource
8. RP get the redirection to OP's USERINFO endpoint, using the access token got before


## Proposed resources namespace
Add them to `urls.py` if needed, then updated oidc_op `conf.yaml`.

- /oidc/endpoint/<provider_name>

## Additional debug notes

- Using [JWTConnect-Python-OidcRP](https://github.com/openid/JWTConnect-Python-OidcRP):

  `RP_LOGFILE_NAME="./flrp.django.log" python3 -m flask_rp.wsgi flask_rp/conf.django.yaml`
