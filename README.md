# django-oidc-op
A Django implementation of a OIDC OP on top of [Roland Hedberg oidc-op](https://github.com/rohe/oidc-op).

## Status
Work in Progress, please wait for the first release tag before considering it ready to use.

Available resources:

- /.well-known/webfinger [to be tested]
- /.well-known/openid-configuration [tested, working]

- /registration [tested, working]
- /authorization [tested, working]

- login form [wip]

## Run the example demo

````
git clone https://github.com/peppelinux/django-oidc-op.git
cd django-oidc-op

pip install -r requirements.txt

cd example
./manage.py migrate
./manage.py createsuperuser

gunicorn example.wsgi -b0.0.0.0:8000 --keyfile=./data/oidc_op/certs/key.pem --certfile=./data/oidc_op/certs/cert.pem --reload
````

## Configure OIDC endpoint

These following files needed to be present in `data/oidc_op/private`.

1. session.json (JWK symmetric)
2. cookie_sign_jwk.json (JWK symmetric)
3. passwd.json: deprecated, optional. To be replaced with Django internals.
4. users.json: deprecated, optional. To be replaced with Django internals.

## General description

The example included in the example enables dynamic registration of RPs.
Using an example RP like [JWTConnect-Python-OidcRP](https://github.com/openid/JWTConnect-Python-OidcRP) and configuring in its `CLIENTS` configuration section to use django-oidc-op, we'll see the following flow happen:

1. /.well-known/openid-configuration
   RP get the OP configuration (metadata)
2. /registration
   RP registers in the OP
3. /authorization
   RP mades OIDC authorization
4. RP going to be redirected to login form page

## Proposed resources namespace
Add them to `urls.py` if needed, then updated oidc_op `conf.yaml`.

- /oidc/endpoint/<provider_name>
