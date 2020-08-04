#!/bin/bash

python setup.py sdist
cd dist
tar zxvf *.tar.gz
cd python-gnutls-?.?.?
debuild --no-sign