%define use-stable	1
%if %{use-stable}
  %define version 	3.0.2p1
  %define cvs		%{nil}
  %define release 	1
%else
  %define version 	3.0p1
  %define cvs		cvs20011102
  %define release 	0r1
%endif
%define xsa		x11-ssh-askpass		
%define askpass		%{xsa}-1.2.4.1

Name        	: openssh
Version     	: %{version}%{cvs}
Release     	: %{release}
Group       	: System/Network

Summary     	: OpenSSH free Secure Shell (SSH) implementation.

Copyright   	: BSD
Packager    	: Raymund Will <ray@caldera.de>
URL         	: http://www.openssh.com/

Obsoletes   	: ssh, ssh-clients, openssh-clients

BuildRoot   	: /tmp/%{Name}-%{Version}

# %{use-stable}==1:	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable
# %{use-stable}==0:	:pserver:cvs@bass.directhit.com:/cvs/openssh_cvs
Source0: see-above:/.../openssh-%{Version}.tar.gz
%if %{use-stable}
Source1: see-above:/.../openssh-%{Version}.tar.gz.sig
%endif
Source2: http://www.ntrnet.net/~jmknoble/software/%{xsa}/%{askpass}.tar.gz
Source3: http://www.openssh.com/faq.html


%Package server
Group       	: System/Network
Requires    	: openssh = %{Version}
Obsoletes   	: ssh-server

Summary     	: OpenSSH Secure Shell protocol server (sshd).


%Package askpass
Group       	: System/Network
Requires    	: openssh = %{Version}
URL       	: http://www.ntrnet.net/~jmknoble/software/x11-ssh-askpass/
Obsoletes   	: ssh-extras

Summary     	: OpenSSH X11 pass-phrase dialog.


%Prep
%setup %([ -z "%{cvs}" ] || echo "-n %{Name}_cvs") -a2

%if ! %{use-stable}
  autoreconf
%endif


%Build
CFLAGS="$RPM_OPT_FLAGS" \
./configure \
            --prefix=/usr \
            --sysconfdir=/etc/ssh \
            --libexecdir=/usr/lib/ssh \
            --with-pam \
            --with-tcp-wrappers \
            --with-ipv4-default \

make

cd %{askpass}
./configure
xmkmf
make includes
make


%Install
%{mkDESTDIR}

make DESTDIR="$DESTDIR" install

make -C %{askpass} BINDIR="/usr/lib/ssh" install

# OpenLinux specific configuration
mkdir -p $DESTDIR/{etc/pam.d,%{SVIcdir},%{SVIdir}}

# enabling X11 forwarding on the server is convenient and okay,
# on the client side we consider it a potential security risk!
%{fixUP} -vT  $DESTDIR/etc/ssh/sshd_config -e '
   s/X11Forwarding no/X11Forwarding yes/i'

install -m644 contrib/caldera/sshd.pam $DESTDIR/etc/pam.d/sshd
# FIXME: disabled, find out why this doesn't work with NIS
%{fixUP} -vT $DESTDIR/etc/pam.d/sshd -e 's/^(.*pam_limits.*)$/#$1/'

install -m 0755 contrib/caldera/sshd.init $DESTDIR%{SVIdir}/sshd
%{fixUP} -vT $DESTDIR/%{SVIdir} -e 's:\@SVIdir\@:%{SVIdir}: +
   s:\@sysconfdir\@:/etc/ssh:'

cat <<-EoD > $DESTDIR%{SVIcdir}/sshd
	IDENT=sshd
	DESCRIPTIVE="OpenSSH secure shell daemon"
	# This service will be marked as 'skipped' on boot if there
	# is no host key. Use ssh-host-keygen to generate one.
	ONBOOT="yes"
	OPTIONS=""
EoD

SKG=$DESTDIR/usr/sbin/ssh-host-keygen
install -m 0755 contrib/caldera/ssh-host-keygen $SKG
%{fixUP} -T $SKG -e 's:\@sysconfdir\@:/etc/ssh: +
   s:\@sshkeygen\@:/usr/bin/ssh-keygen:'


# install remaining docs
DocD="$DESTDIR%{_defaultdocdir}/%{Name}-%{Version}"; mkdir -p $DocD/00-LEGAL
cp -a LICENCE $DocD/00-LEGAL
cp -a CREDITS ChangeLog OVERVIEW README* TODO  $DocD
install -p -m 0444 -o 0 -g 0 %{SOURCE3}  $DocD/faq.html
mkdir -p $DocD/%{askpass}
cp -a %{askpass}/{README,ChangeLog,TODO,SshAskpass*.ad}  $DocD/%{askpass}

cp -p %{askpass}/%{xsa}.man $DESTDIR/usr/man/man1/%{xsa}.1
ln -s  %{xsa}.1 $DESTDIR/usr/man/man1/ssh-askpass.1

%{fixManPages}


# generate file lists
%{mkLists} -c %{Name}
%{mkLists} -d %{Name} << 'EOF'
/etc/ssh				base
^/etc/					IGNORED
%{_defaultdocdir}/$			IGNORED
askpass					askpass
*					default
EOF
%{mkLists} -a -f %{Name} << 'EOF'
^/etc					*		prefix(%%config)
/usr/X11R6/lib/X11/app-defaults 	IGNORED
Ssh.bin 				IGNORED		# for now
[Aa]skpass				askpass
%{_defaultdocdir}/%{Name}-%{Version}/	base
ssh-keygen				base
moduli					server
sshd					server
sftp-server				server
.*					base
EOF


%Clean
%{rmDESTDIR}


%Post
# Generate host key when none is present to get up and running,
# both client and server require this for host-based auth!
# ssh-host-keygen checks for existing keys.
/usr/sbin/ssh-host-keygen
: # to protect the rpm database


%Post server
if [ -x %{LSBinit}-install ]; then
  %{LSBinit}-install sshd
else
  lisa --SysV-init install sshd S55 3:4:5 K45 0:1:2:6
fi

! %{SVIdir}/sshd status || %{SVIdir}/sshd restart
: # to protect the rpm database


%PreUn server
[ "$1" = 0 ] || exit 0

! %{SVIdir}/sshd status || %{SVIdir}/sshd stop
: # to protect the rpm database


%PostUn server
if [ -x %{LSBinit}-remove ]; then
  %{LSBinit}-remove sshd
else
  lisa --SysV-init remove sshd $1
fi
: # to protect the rpm database


%Files -f files-%{Name}-base
%defattr(-,root,root)


%Files server -f files-%{Name}-server
%defattr(-,root,root)


%Files askpass -f files-%{Name}-askpass
%defattr(-,root,root)


%Description
OpenSSH (Secure Shell) provides access to a remote system. It replaces
telnet, rlogin,  rexec, and rsh, and provides secure encrypted 
communications between two untrusted hosts over an insecure network.  
X11 connections and arbitrary TCP/IP ports can also be forwarded over 
the secure channel.

%Description server
This package installs the sshd, the server portion of OpenSSH. 

%Description askpass
This package contains an X11-based pass-phrase dialog used per
default by ssh-add(1). It is based on %{askpass}
by Jim Knoble <jmknoble@pobox.com>.

%ChangeLog
* Mon Jan 01 1998 ...

$Id: openssh.spec,v 1.26 2002/01/26 06:45:15 djm Exp $
