#!/bin/sh
#
# buildbff.sh: Create AIX SMIT-installable OpenSSH packages
#
# Author: Darren Tucker (dtucker at zip dot com dot au)
# This file is placed in the public domain and comes with absolutely
# no warranty.
# 
# Based originally on Ben Lindstrom's buildpkg.sh for Solaris
#

umask 022
PKGNAME=openssh
PKGDIR=package

PATH=`pwd`:$PATH		# set path for external tools
export PATH

# Clean build directory 
rm -rf $PKGDIR
mkdir $PKGDIR

if [ ! -f ../../Makefile ]
then
	echo "Top-level Makefile not found (did you run ./configure?)"
	exit 1
fi

## Start by faking root install 
echo "Faking root install..."
START=`pwd`
FAKE_ROOT=$START/$PKGDIR
cd ../.. 
make install-nokeys DESTDIR=$FAKE_ROOT

if [ $? -gt 0 ]
then
	echo "Fake root install failed, stopping."
	exit 1
fi

#
# Extract common info requires for the 'info' part of the package.
#	AIX requires 4-part version numbers
#
VERSION=`./ssh -V 2>&1 | sed -e 's/,.*//' | cut -f 2 -d _`
MAJOR=`echo $VERSION | cut -f 1 -d p | cut -f 1 -d .`
MINOR=`echo $VERSION | cut -f 1 -d p | cut -f 2 -d .`
PATCH=`echo $VERSION | cut -f 1 -d p | cut -f 3 -d .`
PORTABLE=`echo $VERSION | cut -f 2 -d p`
if [ "$PATCH" = "" ]
then
	PATCH=0
fi
BFFVERSION=`printf "%d.%d.%d.%d" $MAJOR $MINOR $PATCH $PORTABLE`

echo "Building BFF for $PKGNAME $VERSION (package version $BFFVERSION)"

#
# Fill in some details, like prefix and sysconfdir
#	the eval also expands variables like sysconfdir=${prefix}/etc
#	provided they are eval'ed in the correct order
#
for confvar in prefix exec_prefix bindir sbindir libexecdir datadir mandir mansubdir sysconfdir piddir
do
	eval $confvar=`grep "^$confvar=" Makefile | cut -d = -f 2`
done

# Rename config files; postinstall script will copy them if necessary
for cfgfile in ssh_config sshd_config ssh_prng_cmds
do
	mv $FAKE_ROOT/$sysconfdir/$cfgfile $FAKE_ROOT/$sysconfdir/$cfgfile.default
done

#
# Generate lpp control files.
#	working dir is $FAKE_ROOT but files are generated in contrib/aix
#	and moved into place just before creation of .bff
#
cd $FAKE_ROOT
echo Generating LPP control files
find . ! -name . -print >../openssh.al
inventory.sh >../openssh.inventory
cp ../../../LICENCE ../openssh.copyright

#
# Create postinstall script
#
cat <<EOF >>../openssh.post_i
#!/bin/sh

# Create configs from defaults if necessary
for cfgfile in ssh_config sshd_config ssh_prng_cmds
do
        if [ ! -f $sysconfdir/\$cfgfile ]
        then
                echo "Creating \$cfgfile from default"
                cp $sysconfdir/\$cfgfile.default $sysconfdir/\$cfgfile
        else
                echo "\$cfgfile already exists."
        fi
done

# Generate keys unless they already exist
if [ -f "$sysconfdir/ssh_host_key" ] ; then
        echo "$sysconfdir/ssh_host_key already exists, skipping."
else
        $bindir/ssh-keygen -t rsa1 -f $sysconfdir/ssh_host_key -N ""
fi
if [ -f $sysconfdir/ssh_host_dsa_key ] ; then
        echo "$sysconfdir/ssh_host_dsa_key already exists, skipping."
else
        $bindir/ssh-keygen -t dsa -f $sysconfdir/ssh_host_dsa_key -N ""
fi
if [ -f $sysconfdir/ssh_host_rsa_key ] ; then
        echo "$sysconfdir/ssh_host_rsa_key already exists, skipping."
else 
        $bindir/ssh-keygen -t rsa -f $sysconfdir/ssh_host_rsa_key -N ""
fi

# Add to system startup if required
if grep $sbindir/sshd /etc/rc.tcpip >/dev/null
then
        echo "sshd found in rc.tcpip, not adding."
else
        echo >>/etc/rc.tcpip
        echo "echo Starting sshd" >>/etc/rc.tcpip
        echo "$sbindir/sshd" >>/etc/rc.tcpip
fi
EOF

#
# Create liblpp.a and move control files into it
#
echo Creating liblpp.a
(
	cd ..
	for i in al copyright inventory post_i
	do
		ar -r liblpp.a openssh.$i
		rm openssh.$i
	done
)

#
# Create lpp_name
#
# This will end up looking something like:
# 4 R I OpenSSH {
# OpenSSH 3.0.2.1 1 N U en_US OpenSSH 3.0.2p1 Portable for AIX
# [
# %
# /usr/local/bin 8073
# /usr/local/etc 189
# /usr/local/libexec 185
# /usr/local/man/man1 145
# /usr/local/man/man8 83
# /usr/local/sbin 2105
# /usr/local/share 3
# %
# ]
echo Creating lpp_name
cat <<EOF >../lpp_name
4 R I $PKGNAME {
$PKGNAME $BFFVERSION 1 N U en_US OpenSSH $VERSION Portable for AIX
[
%
EOF

for i in $bindir $sysconfdir $libexecdir $mandir/man1 $mandir/man8 $sbindir $datadir
do
	# get size in 512 byte blocks
	size=`du $FAKE_ROOT/$i | awk '{print $1}'`
	echo "$i $size" >>../lpp_name
done

echo '%' >>../lpp_name
echo ']' >>../lpp_name
echo '}' >>../lpp_name

#
# Move pieces into place
#
mkdir -p usr/lpp/openssh
mv ../liblpp.a usr/lpp/openssh
mv ../lpp_name .

#
# Now invoke backup to create .bff file
#	note: lpp_name needs to be the first file do we generate the
#	file list on the fly and feed it to backup using -i
#
echo Creating $PKGNAME-$VERSION.bff with backup...
rm -f $PKGNAME-$VERSION.bff
(
	echo "./lpp_name"
	find . ! -name lpp_name -a ! -name . -print 
) | backup  -i -q -f ../$PKGNAME-$VERSION.bff $filelist

cd ..

rm -rf $PKGDIR
echo $0: done.

