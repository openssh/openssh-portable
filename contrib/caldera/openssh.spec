# Version of OpenSSH
%define oversion 2.5.2p1

# Version of ssh-askpass
%define aversion 1.2.0

# Do we want to disable building of x11-askpass? (1=yes 0=no)
%define no_x11_askpass 0

# Do we want to disable building of gnome-askpass? (1=yes 0=no)
%define no_gnome_askpass 1

# Do we want to include contributed programs? (1=yes 0=no)
%define contrib_programs 1

Summary: OpenSSH free Secure Shell (SSH) implementation
Name: openssh
Version: %{oversion}
Release: 1
Packager: Damien Miller <djm@mindrot.org>
URL: http://www.openssh.com/
Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{oversion}.tar.gz
Source1: http://www.ntrnet.net/~jmknoble/software/x11-ssh-askpass/x11-ssh-askpass-%{aversion}.tar.gz 
Copyright: BSD
Group: Applications/Internet
BuildRoot: /var/tmp/openssh-%{Version}-buildroot
#BuildRoot: /tmp/openssh-%{Version}-buildroot
Obsoletes: ssh
PreReq: openssl >= 0.9.5a
Requires: openssl >= 0.9.5a
BuildPreReq: perl, openssl-devel, tcp_wrappers
BuildPreReq: /bin/login, /usr/bin/rsh, /usr/include/security/pam_appl.h
%if ! %{no_gnome_askpass}
BuildPreReq: gnome-libs-devel
%endif

%package clients
Summary: OpenSSH Secure Shell protocol clients
Requires: openssh = %{Version}-%{release}
Group: Applications/Internet
Obsoletes: ssh-clients

%package server
Summary: OpenSSH Secure Shell protocol server (sshd)
Group: System Environment/Daemons
Obsoletes: ssh-server
#PreReq: openssh chkconfig >= 0.9

%package askpass
Summary: OpenSSH X11 passphrase dialog
Group: Applications/Internet
Requires: openssh = %{Version}-%{release}
Obsoletes: ssh-extras

%package askpass-gnome
Summary: OpenSSH GNOME passphrase dialog
Group: Applications/Internet
Requires: openssh = %{Version}-%{release}
Obsoletes: ssh-extras

%description
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package includes the core files necessary for both the OpenSSH
client and server.  To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%description clients
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package includes the clients necessary to make encrypted connections
to SSH servers.

%description server
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains the secure shell daemon. The sshd is the server 
part of the secure shell protocol and allows ssh clients to connect to 
your host.

%description askpass
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains Jim Knoble's <jmknoble@pobox.com> X11 passphrase 
dialog.

%description askpass-gnome
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains the GNOME passphrase dialog.

%prep

%setup -a 1

%build

%define _sysconfdir /etc/ssh

CFLAGS="$RPM_OPT_FLAGS"					\
	./configure					\
		--prefix=/usr				\
		--sysconfdir=/etc/ssh			\
		--libexecdir=%{_libexecdir}/openssh	\
		--with-pam \
		--with-tcp-wrappers			\
		--with-ipv4-default			\
		--with-rsh=/usr/bin/rsh

make

%if ! %{no_x11_askpass}
cd x11-ssh-askpass-%{aversion}
xmkmf -a
make
cd ..
%endif

%if ! %{no_gnome_askpass}
cd contrib
gcc -O -g `gnome-config --cflags gnome gnomeui` \
        gnome-ssh-askpass.c -o gnome-ssh-askpass \
        `gnome-config --libs gnome gnomeui`
cd ..
%endif

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT/

# setup the environment we want
perl -pi -e "s,PermitRootLogin yes,PermitRootLogin no,;" \
	 -e "s,X11Forwarding no,X11Forwarding yes,;" \
	 -e "s,CheckMail no,CheckMail yes,;" \
	 -e "s,^#Subsystem	sftp,Subsystem	sftp,;" \
	$RPM_BUILD_ROOT/etc/ssh/sshd_config

install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT/etc/sysconfig/daemons
install -d $RPM_BUILD_ROOT%{_libexecdir}/openssh
install -d $RPM_BUILD_ROOT/usr/local/bin
install -d $RPM_BUILD_ROOT/usr/local/man/man1
install -m644 contrib/caldera/sshd.pam $RPM_BUILD_ROOT/etc/pam.d/sshd
install -m755 contrib/caldera/sshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install -m755 contrib/caldera/sshd.daemons $RPM_BUILD_ROOT/etc/sysconfig/daemons/sshd
perl -pi -e "s,\@OPENSSH_VERSION\@,%{Name}-%{Version},g" \
	$RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
perl -pi -e "s,\@OPENSSH_VERSION\@,%{Name}-%{Version},g" \
	$RPM_BUILD_ROOT/etc/sysconfig/daemons/sshd
%if %{contrib_programs}
install -m755 contrib/make-ssh-known-hosts.pl $RPM_BUILD_ROOT/usr/local/bin
install -m644 contrib/make-ssh-known-hosts.1 $RPM_BUILD_ROOT/usr/local/man/man1
install -m755 contrib/ssh-copy-id $RPM_BUILD_ROOT/usr/local/bin
install -m644 contrib/ssh-copy-id.1 $RPM_BUILD_ROOT/usr/local/man/man1
%endif

%if ! %{no_x11_askpass}
install -s x11-ssh-askpass-%{aversion}/x11-ssh-askpass $RPM_BUILD_ROOT/usr/libexec/openssh/x11-ssh-askpass
ln -s /usr/libexec/openssh/x11-ssh-askpass $RPM_BUILD_ROOT/usr/libexec/openssh/ssh-askpass
install -d $RPM_BUILD_ROOT/usr/X11R6/man/man1
install -c -m 0444 x11-ssh-askpass-%{aversion}/x11-ssh-askpass.man $RPM_BUILD_ROOT/usr/X11R6/man/man1/x11-ssh-askpass.1x
ln -s /usr/X11R6/man/man1/x11-ssh-askpass.1x $RPM_BUILD_ROOT/usr/X11R6/man/man1/ssh-askpass.1x
%endif

%if ! %{no_gnome_askpass}
install -s contrib/gnome-ssh-askpass $RPM_BUILD_ROOT/usr/libexec/openssh/gnome-ssh-askpass
%endif

%clean
##rm -rf $RPM_BUILD_ROOT

%post server
if [ "$1" = 1 ]; then
	echo "Creating SSH stop/start scripts in the rc directories..."
#	/sbin/chkconfig --add sshd
	lisa --SysV-init install sshd S90 2:3:4:5 K05 0:1:6
fi
if test -r /var/run/sshd.pid
then
        echo "Restarting the running SSH daemon..."
	/etc/rc.d/init.d/sshd restart >&2
else
        echo "Starting the SSH daemon..."
	/etc/rc.d/init.d/sshd start >&2
fi

%preun server
if [ "$1" = 0 ] ; then
        echo "Stopping the SSH daemon..."
	/etc/rc.d/init.d/sshd stop >&2
	echo "Removing SSH stop/start scripts from the rc directories..."
#	/sbin/chkconfig --del sshd
	lisa --SysV-init remove  sshd $1
fi

%files
%defattr(-,root,root)
%doc ChangeLog OVERVIEW README* INSTALL 
%doc CREDITS LICENCE
%attr(0755,root,root) %{_bindir}/ssh-keygen
%attr(0755,root,root) %{_bindir}/scp
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0644,root,root) %{_mandir}/man1/ssh-keygen.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %{_mandir}/man1/scp.1*
%attr(0755,root,root) %dir %{_sysconfdir}
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/primes
%attr(0755,root,root) %dir %{_libexecdir}/openssh

%files clients
%defattr(-,root,root)
%attr(4755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0755,root,root) %{_bindir}/sftp
%attr(0644,root,root) %{_mandir}/man1/ssh.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-agent.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-add.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh_config
%attr(-,root,root) %{_bindir}/slogin
%attr(-,root,root) %{_mandir}/man1/slogin.1*
%if %{contrib_programs}
%attr(0755,root,root) /usr/local/bin/make-ssh-known-hosts.pl 
%attr(0644,root,root) /usr/local/man/man1/make-ssh-known-hosts.1 
%attr(0755,root,root) /usr/local/bin/ssh-copy-id 
%attr(0644,root,root) /usr/local/man/man1/ssh-copy-id.1 
%endif

%files server
%defattr(-,root,root)
%attr(0751,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %{_libexecdir}/openssh/sftp-server
%attr(0644,root,root) %{_mandir}/man8/sshd.8*
%attr(0644,root,root) %{_mandir}/man8/sftp-server.8*
#%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/sshd_config
%attr(0600,root,root) %config %{_sysconfdir}/sshd_config
%attr(0600,root,root) %config(noreplace) /etc/pam.d/sshd
%attr(0755,root,root) %config /etc/rc.d/init.d/sshd
%attr(0755,root,root) %config /etc/sysconfig/daemons/sshd

%if ! %{no_x11_askpass}
%files askpass
%defattr(-,root,root)
%doc x11-ssh-askpass-%{aversion}/README
%doc x11-ssh-askpass-%{aversion}/ChangeLog
%doc x11-ssh-askpass-%{aversion}/SshAskpass*.ad
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-askpass
%attr(0755,root,root) %{_libexecdir}/openssh/x11-ssh-askpass
%attr(0644,root,root) /usr/X11R6/man/man1/x11-ssh-askpass.1x
%attr(-,root,root) /usr/X11R6/man/man1/ssh-askpass.1x
%endif

%if ! %{no_gnome_askpass}
%files askpass-gnome
%defattr(-,root,root)
%attr(0755,root,root) %{_libexecdir}/openssh/gnome-ssh-askpass
%endif

%changelog
* Mon Oct 18 2000 Damien Miller <djm@mindrot.org>
- Merge some of Nalin Dahyabhai <nalin@redhat.com> changes from the 
  Redhat 7.0 spec file
* Tue Sep 05 2000 Damien Miller <djm@mindrot.org>
- Use RPM configure macro
* Tue Aug 08 2000 Damien Miller <djm@mindrot.org>
- Some surgery to sshd.init (generate keys at runtime)
- Cleanup of groups and removal of keygen calls
* Wed Jul 12 2000 Damien Miller <djm@mindrot.org>
- Make building of X11-askpass and gnome-askpass optional
* Mon Jun 12 2000 Damien Miller <djm@mindrot.org>
- Glob manpages to catch compressed files
* Wed Mar 15 2000 Damien Miller <djm@ibs.com.au>
- Updated for new location
- Updated for new gnome-ssh-askpass build
* Sun Dec 26 1999 Damien Miller <djm@mindrot.org>
- Added Jim Knoble's <jmknoble@pobox.com> askpass
* Mon Nov 15 1999 Damien Miller <djm@mindrot.org>
- Split subpackages further based on patch from jim knoble <jmknoble@pobox.com>
* Sat Nov 13 1999 Damien Miller <djm@mindrot.org>
- Added 'Obsoletes' directives
* Tue Nov 09 1999 Damien Miller <djm@ibs.com.au>
- Use make install
- Subpackages
* Mon Nov 08 1999 Damien Miller <djm@ibs.com.au>
- Added links for slogin
- Fixed perms on manpages
* Sat Oct 30 1999 Damien Miller <djm@ibs.com.au>
- Renamed init script
* Fri Oct 29 1999 Damien Miller <djm@ibs.com.au>
- Back to old binary names
* Thu Oct 28 1999 Damien Miller <djm@ibs.com.au>
- Use autoconf
- New binary names
* Wed Oct 27 1999 Damien Miller <djm@ibs.com.au>
- Initial RPMification, based on Jan "Yenya" Kasprzak's <kas@fi.muni.cz> spec.

