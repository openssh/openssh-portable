# Version of OpenSSH
%define oversion 2.9p1

# Version of ssh-askpass
%define aversion 1.2.2

# Do we want to disable building of x11-askpass? (1=yes 0=no)
%define no_x11_askpass 0

# Do we want to disable building of gnome-askpass? (1=yes 0=no)
%define no_gnome_askpass 0

# Do we want to link against a static libcrypto? (1=yes 0=no)
%define static_libcrypto 0

# Use Redhat 7.0 pam control file
%define redhat7 0

# Reserve options to override askpass settings with:
# rpm -ba|--rebuild --define 'skip_xxx 1'
%{?skip_x11_askpass:%define no_x11_askpass 1}
%{?skip_gnome_askpass:%define no_gnome_askpass 1}

# Options for Redhat version:
# rpm -ba|--rebuild --define "rh7 1"
%{?rh7:%define redhat7 1}

# Options for static OpenSSL link:
# rpm -ba|--rebuild --define "static_openssl 1"
%{?static_openssl:%define static_libcrypto 1}

%define exact_openssl_version   %(rpm -q openssl | cut -d - -f 2)

Summary: OpenSSH free Secure Shell (SSH) implementation
Name: openssh
Version: %{oversion}
Release: 1
Packager: Damien Miller <djm@mindrot.org>
URL: http://www.openssh.com/
Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{oversion}.tar.gz
%if ! %{no_x11_askpass}
Source1: http://www.jmknoble.cx/software/x11-ssh-askpass/x11-ssh-askpass-%{aversion}.tar.gz 
%endif
Copyright: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Obsoletes: ssh
BuildPreReq: perl, openssl-devel, tcp_wrappers
BuildPreReq: /bin/login, /usr/include/security/pam_appl.h
BuildPreReq: rpm >= 3.0.5
%if ! %{no_gnome_askpass}
BuildPreReq: gnome-libs-devel
%endif
%if ! %{static_libcrypto}
PreReq: openssl >= 0.9.5a
PreReq: openssl = %{exact_openssl_version}
Requires: openssl >= 0.9.5a
%endif
Requires: rpm >= 3.0.5

%package clients
Summary: OpenSSH Secure Shell protocol clients
Requires: openssh = %{version}-%{release}
Group: Applications/Internet
Obsoletes: ssh-clients

%package server
Summary: OpenSSH Secure Shell protocol server (sshd)
Group: System Environment/Daemons
Obsoletes: ssh-server
PreReq: openssh = %{version}-%{release}, chkconfig >= 0.9
%if %{redhat7}
Requires: /etc/pam.d/system-auth
%endif

%package askpass
Summary: OpenSSH X11 passphrase dialog
Group: Applications/Internet
Requires: openssh = %{version}-%{release}
Obsoletes: ssh-extras

%package askpass-gnome
Summary: OpenSSH GNOME passphrase dialog
Group: Applications/Internet
Requires: openssh = %{version}-%{release}
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

This package contains Jim Knoble's <jmknoble@jmknoble.cx> X11 passphrase 
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

%if ! %{no_x11_askpass}
%setup -q -a 1
%else
%setup -q
%endif

%build

%define _sysconfdir /etc/ssh

%configure \
	--libexecdir=%{_libexecdir}/openssh \
	--with-pam \
	--with-tcp-wrappers \
	--with-ipv4-default \
	--with-rsh=/usr/bin/rsh \
	--with-default-path=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin

%if %{static_libcrypto}
perl -pi -e "s|-lcrypto|/usr/lib/libcrypto.a|g" Makefile
%endif

make

%if ! %{no_x11_askpass}
pushd x11-ssh-askpass-%{aversion}
xmkmf -a
make
popd
%endif

%if ! %{no_gnome_askpass}
pushd contrib
gcc -O -g `gnome-config --cflags gnome gnomeui` \
        gnome-ssh-askpass.c -o gnome-ssh-askpass \
        `gnome-config --libs gnome gnomeui`
popd
%endif

%install
rm -rf $RPM_BUILD_ROOT
%{makeinstall} \
	libexecdir=$RPM_BUILD_ROOT%{_libexecdir}/openssh \
	DESTDIR=/ # Hack to disable key generation


install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT%{_libexecdir}/openssh
%if %{redhat7}
install -m644 contrib/redhat/sshd.pam-7.x $RPM_BUILD_ROOT/etc/pam.d/sshd
%else
install -m644 contrib/redhat/sshd.pam $RPM_BUILD_ROOT/etc/pam.d/sshd
%endif
install -m755 contrib/redhat/sshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd

%if ! %{no_x11_askpass}
install -s x11-ssh-askpass-%{aversion}/x11-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/x11-ssh-askpass
ln -s /usr/libexec/openssh/x11-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/ssh-askpass
%endif

%if ! %{no_gnome_askpass}
install -s contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/gnome-ssh-askpass
%endif

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

%clean
rm -rf $RPM_BUILD_ROOT

%post server
/sbin/chkconfig --add sshd
if test -r /var/run/sshd.pid ; then
	/etc/rc.d/init.d/sshd restart >&2
fi

%preun server
if [ "$1" = 0 ] ; then
	/etc/rc.d/init.d/sshd stop >&2
	/sbin/chkconfig --del sshd
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
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/moduli
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

%files server
%defattr(-,root,root)
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %{_libexecdir}/openssh/sftp-server
%attr(0644,root,root) %{_mandir}/man8/sshd.8*
%attr(0644,root,root) %{_mandir}/man8/sftp-server.8*
#%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/sshd_config
%attr(0600,root,root) %config %{_sysconfdir}/sshd_config
%attr(0600,root,root) %config(noreplace) /etc/pam.d/sshd
%attr(0755,root,root) %config /etc/rc.d/init.d/sshd

%if ! %{no_x11_askpass}
%files askpass
%defattr(-,root,root)
%doc x11-ssh-askpass-%{aversion}/README
%doc x11-ssh-askpass-%{aversion}/ChangeLog
%doc x11-ssh-askpass-%{aversion}/SshAskpass*.ad
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-askpass
%attr(0755,root,root) %{_libexecdir}/openssh/x11-ssh-askpass
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

