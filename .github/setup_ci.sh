#!/usr/bin/env bash

case $(./config.guess) in
*-darwin*)
	# no setup needed for Mac OS X
	exit 0
	;;
esac

TARGETS=$@

PACKAGES=""
INSTALL_FIDO_PPA="no"

#echo "Setting up for '$TARGETS'"

set -ex

lsb_release -a

for TARGET in $TARGETS; do
    case $TARGET in
    ""|--without-openssl|--without-zlib)
        # nothing to do
        ;;
    "--with-kerberos5")
        PACKAGES="$PACKAGES heimdal-dev"
        #PACKAGES="$PACKAGES libkrb5-dev"
        ;;
    "--with-libedit")
        PACKAGES="$PACKAGES libedit-dev"
        ;;
    "--with-pam")
        PACKAGES="$PACKAGES libpam0g-dev"
        ;;
    "--with-security-key-builtin")
        INSTALL_FIDO_PPA="yes"
        PACKAGES="$PACKAGES libfido2-dev libu2f-host-dev"
        ;;
    "--with-selinux")
        PACKAGES="$PACKAGES libselinux1-dev selinux-policy-dev"
        ;;
    "--with-ldflags=-lhardened_malloc")
        INSTALL_HARDENED_MALLOC=yes
       ;;
    *) echo "Invalid option '${TARGET}'"
        exit 1
        ;;
    esac
done

if [ "yes" == "$INSTALL_FIDO_PPA" ]; then
    sudo apt update -qq
    sudo apt install software-properties-common
    sudo apt-add-repository ppa:yubico/stable
fi

if [ "x" != "x$PACKAGES" ]; then 
    sudo apt update -qq
    sudo apt install -qy $PACKAGES
fi

if [ "${INSTALL_HARDENED_MALLOC}" = "yes" ]; then
    (cd ${HOME} &&
     git clone https://github.com/GrapheneOS/hardened_malloc.git &&
     cd ${HOME}/hardened_malloc &&
     make && sudo cp libhardened_malloc.so /usr/lib/)
fi
