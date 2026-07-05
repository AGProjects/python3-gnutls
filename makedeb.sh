#!/bin/bash

set -e

# install the tools and the build dependencies declared in debian/control
sudo apt-get install -y --no-install-recommends devscripts equivs python3-build python3-venv
sudo mk-build-deps --install --remove --tool 'apt-get -y --no-install-recommends' debian/control
rm -f python3-gnutls-build-deps_*.deb python3-gnutls-build-deps_*.buildinfo python3-gnutls-build-deps_*.changes

rm -rf dist

# build the source distribution (pyproject.toml or legacy setup.py layout)
if [ -f pyproject.toml ]; then
    python3 -m build --sdist
else
    python3 setup.py sdist
fi

cd dist
tar zxvf *.tar.gz

cd python3*gnutls-*/

debuild --no-sign
