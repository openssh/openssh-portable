#!/bin/sh

ver=1.8.32

set -e

timeout 600 ftp ftp://ftp.sudo.ws/pub/sudo/sudo-${ver}.tar.gz || \
    ftp ftp://ftp.sudo.ws/pub/sudo/sudo-${ver}.tar.gz
tar xfz sudo-${ver}.tar.gz

cd sudo-${ver}
./configure --sysconfdir=/usr/local/etc
make
make install
