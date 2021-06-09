#!/bin/bash

###########
# Build OpenSSH
#
# Must be run after OQS has been installed
###########

set -exo pipefail

INSTALL_PREFIX=${INSTALL_PREFIX:-"`pwd`/oqs-test/tmp"}
WITH_OPENSSL=${WITH_OPENSSL:-"true"}

case "$OSTYPE" in
    darwin*)  OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr/local/opt/openssl@1.1"} ;;
    linux*)   OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr"} ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

if [ -f Makefile ]; then
    make clean
else
    autoreconf -i
fi

if [ "x${WITH_OPENSSL}" == "xtrue" ]; then
    ./configure --prefix="${INSTALL_PREFIX}" --with-ldflags="-Wl,-rpath -Wl,${INSTALL_PREFIX}/lib" --with-libs=-lm --with-ssl-dir="${OPENSSL_SYS_DIR}" --with-liboqs-dir="`pwd`/oqs" --with-cflags="-Wno-implicit-function-declaration -I${INSTALL_PREFIX}/include" --sysconfdir="${INSTALL_PREFIX}"
else
    ./configure --prefix="${INSTALL_PREFIX}" --with-ldflags="-Wl,-rpath -Wl,${INSTALL_PREFIX}/lib" --with-libs=-lm --without-openssl --with-liboqs-dir="`pwd`/oqs" --with-cflags="-I${INSTALL_PREFIX}/include" --sysconfdir="${INSTALL_PREFIX}"
fi
if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
make install
