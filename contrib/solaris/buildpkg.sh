#!/bin/sh
#
# Fake Root Solaris Build System - Prototype
#
# The following code has been provide under Public Domain License.  I really
# don't care what you use it for.  Just as long as you don't complain to me
# nor my employer if you break it. - Ben Lindstrom (mouring@eviladmin.org)
# 
umask 022
PKGNAME=OpenSSH

## Extract common info requires for the 'info' part of the package.
VERSION=`tail -1 ../../version.h | sed -e 's/.*_\([0-9]\)/\1/g' | sed 's/\"$//'`
ARCH=`uname -p`

## Start by faking root install 
echo "Faking root install..."
START=`pwd`
FAKE_ROOT=$START/package
mkdir $FAKE_ROOT
cd ../..
make install-nokeys DESTDIR=$FAKE_ROOT

## Fill in some details, like prefix and sysconfdir
ETCDIR=`grep "^sysconfdir=" Makefile | sed 's/sysconfdir=//'`
PREFIX=`grep "^prefix=" Makefile | cut -d = -f 2`        
cd $FAKE_ROOT

## Setup our run level stuff while we are at it.
mkdir -p $FAKE_ROOT/etc/init.d
mkdir -p $FAKE_ROOT/etc/rcS.d
mkdir -p $FAKE_ROOT/etc/rc0.d
mkdir -p $FAKE_ROOT/etc/rc1.d
mkdir -p $FAKE_ROOT/etc/rc2.d


## setup our initscript correctly
sed -e "s#%%configDir%%#$ETCDIR#g" 		\
    -e "s#%%openSSHDir%%#$PREFIX#g"	\
	../opensshd.in	> $FAKE_ROOT/etc/init.d/opensshd
chmod 711 $FAKE_ROOT/etc/init.d/opensshd

ln -s $FAKE_ROOT/etc/init.d/opensshd $FAKE_ROOT/etc/rcS.d/K30opensshd
ln -s $FAKE_ROOT/etc/init.d/opensshd $FAKE_ROOT/etc/rc1.d/K30opensshd
ln -s $FAKE_ROOT/etc/init.d/opensshd $FAKE_ROOT/etc/rc2.d/S98opensshd


## Ok, this is outright wrong, but it will work.  I'm tired of pkgmk
## whining.
for i in *; do
  PROTO_ARGS="$PROTO_ARGS $i=/$i";
done

## Build info file
echo "Building pkginfo file..."
cat > pkginfo << _EOF
PKG=$PKGNAME
NAME=OpenSSH Portable for Solaris
DESC="Secure Shell remote access utility; replaces telnet and rlogin/rsh."
VENDOR="OpenSSH Portable Team - http://www.openssh.com/portable.html"
BASEDIR=$FAKE_ROOT
ARCH=$ARCH
VERSION=$VERSION
CATEGORY=Security
BASEDIR=/
_EOF

## Next Build our prototype
echo "Building prototype file..."
find . | egrep -v "prototype|pkginfo" | sort | pkgproto $PROTO_ARGS | \
	awk '
            BEGIN { print "i pkginfo" }	
	    { $5="root"; $6="sys"; }
	    { print; }' > prototype

## Step back a directory and now build the package.
echo "Building package.."
cd ..
pkgmk -d . -f $FAKE_ROOT/prototype -o
rm -rf $FAKE_ROOT
echo | pkgtrans -os . $PKGNAME-$ARCH-$VERSION.pkg
rm -rf $PKGNAME
