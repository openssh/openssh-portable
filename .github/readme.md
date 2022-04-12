# Secure Server for FerrumGate

This is a fork of [OpenSSH](https://github.com/openssh/openssh-portable) with extended authentication settings.
Aim to create a secure tunnel to your servers (like ssh..) or clusters like (k8s...) or applications (remote desktop...) or services (mysql,postregsql...) with more control.

## Prepare environment

```bash
apt install zlib1g-dev
apt install libssl-dev

```

## Local build for debug

```bash
# prepare external libs for linkage
cd external
bash prepare.libs.sh
cd ../
# auto tools
aclocal
autoconf
autoreconf
# for debugging
./configure --prefix=$(pwd)/build --disable-strip CFLAGS="-W -O0 -g -ggdb -DFERRUM_DEBUG -I$(pwd)/external/libs/include" LDFLAGS="-L$(pwd)/external/libs/lib -lcmocka"
# for prod
./configure --prefix=$(pwd)/buildprod LDFLAGS="-L$(pwd)/../external/libs/lib"
make
make tests #openssh unit tests
make ferrumtests #ferrum unit tests
make install



FERRUM_DEBUG flags is for support SSH with none cipher

```
