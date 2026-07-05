#!/bin/bash

set -e

# install the build tools and the build dependencies from debian/control
sudo apt-get install -y --no-install-recommends devscripts equivs python3-build python3-venv
sudo apt-get build-dep -y --no-install-recommends "$(pwd)"

# make sure the debian package version matches the module version
version=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' gnutls/__info__.py)
deb_version=$(dpkg-parsechangelog -S Version)
if [ "$version" != "$deb_version" ]; then
    echo
    echo "error: debian/changelog version ($deb_version) does not match gnutls/__info__.py ($version)"
    echo "add a changelog entry first, for example:"
    echo
    echo "    dch -v $version -D unstable 'New upstream release'"
    echo
    exit 1
fi

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

echo
echo "Resulting packages:"
ls -l ../*.deb 2>/dev/null || true
