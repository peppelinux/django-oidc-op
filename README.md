# django-oidc-op
A Django implementation of OIDC OP built top of [Roland Hedberg's oidc-op](https://github.com/rohe/oidc-op).

## Status
Work in Progress, please wait for the first release tag before considering it ready to use.

Available resources:

- /.well-known/webfinger [to be tested]
- /.well-known/openid-configuration [tested, working]

- /registration [tested, working]
- /authorization [tested, working]

- login form
- access token
- /userinfo [wip]

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

These following files needed to be present in `data/oidc_op/private`.

1. session.json (JWK symmetric)
2. cookie_sign_jwk.json (JWK symmetric)


The followings was removed and adapted to Django internals:

1. passwd.json
2. users.json

## General description

The example included in this project enables dynamic registration of RPs (you can even disable it).
Using an example RP like [JWTConnect-Python-OidcRP](https://github.com/openid/JWTConnect-Python-OidcRP)
and configuring in `CLIENTS` section to use django-oidc-op (see `example/data/oidc_rp/conf.django.yaml`),
we'll see the following flow happens:

1. /.well-known/openid-configuration
   RP get the OP configuration (metadata)
2. /registration
   RP registers in the OP
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
