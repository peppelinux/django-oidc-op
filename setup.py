import re
import os
import sys

from glob import glob
from setuptools import setup, find_packages

SRC_FOLDER = '.'
PKG_NAME = 'oidc_provider'

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()


#with open(os.path.join(os.path.dirname(__file__), 'requirements.txt')) as requirements:
#    REQUIREMENTS = requirements.read()


setup(
    name="oidc_provider",
    version='2.3.4',
    description="django oidc provider",
    long_description=README,
    long_description_content_type='text/markdown',
    author='Giuseppe De Marco',
    author_email='demarcog83@gmail.com',
    license="Apache 2.0",
    url='https://github.com/peppelinux/django-oidc-op',
    packages=[PKG_NAME,],
    package_dir={PKG_NAME: f'{SRC_FOLDER}/{PKG_NAME}'},

    package_data={PKG_NAME: [i.replace(f'{SRC_FOLDER}/{PKG_NAME}/', '')
                             for i in glob(f'{SRC_FOLDER}/{PKG_NAME}/**',
                                           recursive=True)]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
    "Django>=3.1,<4.1",
    "oidcop==2.3.4"
    ],
    zip_safe=False,
)
