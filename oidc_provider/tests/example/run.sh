#!/bin/bash

./manage.py migrate
./manage.py collectstatic --no-input
./manage.py loaddata test_user.json

gunicorn example.wsgi -b0.0.0.0:8000 --keyfile=./data/oidc_op/certs/key.pem --certfile=./data/oidc_op/certs/cert.pem --reload --timeout 3600 --capture-output --enable-stdio-inheritance

