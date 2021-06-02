# django-oidc-op
A Django implementation of an **OIDC Provider** on top of [jwtconnect.io](https://jwtconnect.io/).
To configure a standard OIDC Provider you have to edit the oidcop configuration file.
See `example/example/settings.py` and `example/example/oidc_provider_settings.py` to get in.

This project is based on [IdentityPython oidc-op](https://github.com/IdentityPython/oidc-op).
Please consult official [oidc-op documentation](https://oidcop.readthedocs.io/en/latest/) for any further information about it's features and capabilities.


## Run the example demo
````
git clone https://github.com/peppelinux/django-oidc-op.git
cd django-oidc-op

pip install -r requirements.txt
cd example

./manage.py createsuperuser

bash run.sh
````

You can use [JWTConnect-Python-OidcRP](https://github.com/openid/JWTConnect-Python-OidcRP) as follow:
```
cd JWTConnect-Python-OidcRP
RP_LOGFILE_NAME="./flrp.django.log" python3 -m flask_rp.wsgi ../django-oidc-op/example/data/oidc_rp/conf.django.yaml
```

You can also use a scripted RP handler on top of oidc-rp
````
python3 snippets/rp_handler.py -c example/data/oidc_rp/conf.django.yaml -u myuser -p mypass -iss django_oidc_op
````


## Configure OIDC endpoint

#### Django settings.py parameters

`OIDCOP_CONFIG`: The path containing the oidc-op configuration file.


## Django specific implementation

This project rely interely on behaviour and features provided by oidcendpoint, to get an exaustive integration in Django it
adopt the following customizations.

#### UserInfo endpoint

Claims to be released are configured in `op.server_info.user_info` (in `oidc_provider_settings.py`).
The attributes release and user authentication mechanism rely on classes implemented in `oidc_op/users.py`.

Configuration Example:

````
      "userinfo": {
        "class": "oidc_provider.users.UserInfo",
        "kwargs": {
            # map claims to django user attributes here:
            "claims_map": {
                "phone_number": "telephone",
                "family_name": "last_name",
                "given_name": "first_name",
                "email": "email",
                "verified_email": "email",
                "gender": "gender",
                "birthdate": "get_oidc_birthdate",
                "updated_at": "get_oidc_lastlogin"
            }
        }
      }
````

#### Relying-Party
![Alt text](images/rp2.png)
![Alt text](images/rp_detail.png)

#### Session management and token preview
![Alt text](images/session_detail.png)
![Alt text](images/issued_token_list.png)
![Alt text](images/issued_token_detail.png)

## OIDC endpoint url prefix
MUST be configured in `urls.py` and also in oidc_op `example/oidc_provider_settings.py`.

- /oidc/endpoint/<provider_name>

## Running tests

running tests
````
./manage.py test oidc_provider
````

## code coverage
````
coverage erase
coverage run manage.py test
coverage report
````
