#!/bin/bash

PROJ_NAME=$(ls | grep *.egg-info | sed -e 's/.egg-info//g') ; rm -R build/ dist/*  *.egg-info ; python setup.py build sdist
twine upload dist/*

