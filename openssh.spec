Summary: OpenSSH free Secure Shell (SSH) implementation
Name: openssh
Version: 1.2pre10
Release: 1
Packager: Damien Miller <djm@ibs.com.au>
Source0: openssh-%{version}.tar.gz
Copyright: BSD
Group: Applications/Internet
BuildRoot: /tmp/openssh-%{version}-buildroot

%package server
Summary: Secure Shell protocol server (sshd)
Requires: openssh chkconfig >= 0.9
Group: System Environment/Daemons

%package askpass
Summary: GNOME passphrase dialog
Group: Applications/Internet
Requires: openssh

%description
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to seperate libraries (OpenSSL).

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
patented algorithms to seperate libraries (OpenSSL).

This package contains the secure shell daemon and its documentation.
The sshd is the server part of the secure shell protocol and allows
ssh clients to connect to your host.

%description askpass
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to seperate libraries (OpenSSL).

This package contains the GNOME passphrase dialog.

%changelog
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

%prep

%setup -n openssh

%build

CFLAGS="$RPM_OPT_FLAGS" \
	./configure --prefix=/usr --sysconfdir=/etc/ssh --with-gnome-askpass

make

%install
rm -rf $RPM_BUILD_ROOT
make install prefix="$RPM_BUILD_ROOT/usr"

install -d $RPM_BUILD_ROOT/etc/ssh
install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m644 sshd.pam $RPM_BUILD_ROOT/etc/pam.d/sshd
install -m755 sshd.init.redhat $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install -m600 ssh_config $RPM_BUILD_ROOT/etc/ssh/ssh_config
install -m600 sshd_config $RPM_BUILD_ROOT/etc/ssh/sshd_config

%clean
rm -rf $RPM_BUILD_ROOT

%post server
/sbin/chkconfig --add sshd
if [ ! -f /etc/ssh/ssh_host_key -o ! -s /etc/ssh/ssh_host_key ]; then
	/usr/bin/ssh-keygen -b 1024 -f /etc/ssh/ssh_host_key -N '' >&2
fi
if test -r /var/run/sshd.pid
then
	/etc/rc.d/init.d/sshd restart >&2
fi

%preun server
if [ "$1" = 0 ]
then
	/etc/rc.d/init.d/sshd stop >&2
	/sbin/chkconfig --del sshd
fi

%files
%defattr(-,root,root)
%doc COPYING.Ylonen ChangeLog ChangeLog.Ylonen OVERVIEW 
%doc README README.Ylonen
%attr(4755,root,root) /usr/bin/ssh
%attr(0755,root,root) /usr/bin/ssh-agent
%attr(0755,root,root) /usr/bin/ssh-keygen
%attr(0755,root,root) /usr/bin/ssh-add
%attr(0755,root,root) /usr/bin/scp
%attr(-,root,root) /usr/bin/slogin
%attr(0644,root,root) /usr/man/man1/ssh.1
%attr(0644,root,root) /usr/man/man1/ssh-agent.1
%attr(0644,root,root) /usr/man/man1/ssh-keygen.1
%attr(0644,root,root) /usr/man/man1/ssh-add.1
%attr(0644,root,root) /usr/man/man1/scp.1
%attr(-,root,root) /usr/man/man1/slogin.1
%attr(0644,root,root) %config /etc/ssh/ssh_config

%files server
%defattr(-,root,root)
%attr(0755,root,root) /usr/sbin/sshd
%attr(0644,root,root) /usr/man/man8/sshd.8
%attr(0600,root,root) %config /etc/ssh/sshd_config
%attr(0600,root,root) %config /etc/pam.d/sshd
%attr(0755,root,root) %config /etc/rc.d/init.d/sshd

%files askpass
%defattr(-,root,root)
%attr(0755,root,root) /usr/lib/ssh/ssh-askpass
