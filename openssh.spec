Summary: OpenSSH free Secure Shell (SSH) implementation
Name: openssh
Version: 1.2pre5
Release: 1
Packager: Damien Miller <djm@ibs.com.au>
Source0: openssh-%{version}-linux.tar.gz
Copyright: BSD
Group: Applications/Internet
BuildRoot: /tmp/openssh-%{version}-buildroot

%description
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to seperate libraries (OpenSSL).

%changelog
* Thu Oct 28 1999 Damien Miller <djm@ibs.com.au>
- Use autoconf
- New binary names
* Wed Oct 27 1999 Damien Miller <djm@ibs.com.au>
- Initial RPMification, based on Jan "Yenya" Kasprzak's <kas@fi.muni.cz> spec.

%prep

%setup -n openssh

%build

./configure --prefix=/usr --sysconfdir=/etc/openssh
make OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin 
mkdir -p $RPM_BUILD_ROOT/usr/sbin 
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
mkdir -p $RPM_BUILD_ROOT/etc/openssh
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/man/man8

install -m644 opensshd.pam $RPM_BUILD_ROOT/etc/pam.d/opensshd
install -m755 opensshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/opensshd
install -m600 ssh_config $RPM_BUILD_ROOT/etc/openssh/ssh_config
install -m600 sshd_config $RPM_BUILD_ROOT/etc/openssh/sshd_config

install -s -m755 bin/opensshd $RPM_BUILD_ROOT/usr/sbin
install -s -m755 bin/openssh $RPM_BUILD_ROOT/usr/bin
install -s -m755 bin/openscp $RPM_BUILD_ROOT/usr/bin
install -s -m755 bin/openssh-agent $RPM_BUILD_ROOT/usr/bin
install -s -m755 bin/openssh-add $RPM_BUILD_ROOT/usr/bin
install -s -m755 bin/openssh-keygen $RPM_BUILD_ROOT/usr/bin

install -m644 opensshd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 openssh.1 $RPM_BUILD_ROOT/usr/man/man1
install -m644 openscp.1 $RPM_BUILD_ROOT/usr/man/man1
install -m644 openssh-agent.1 $RPM_BUILD_ROOT/usr/man/man1
install -m644 openssh-add.1 $RPM_BUILD_ROOT/usr/man/man1
install -m644 openssh-keygen.1 $RPM_BUILD_ROOT/usr/man/man1

# Install compatibility symlinks
cd $RPM_BUILD_ROOT/usr/sbin
ln -s opensshd sshd
cd $RPM_BUILD_ROOT/usr/bin
ln -s openssh ssh
ln -s openscp scp
ln -s openssh-agent ssh-agent
ln -s openssh-add ssh-add
ln -s openssh-keygen ssh-keygen

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add opensshd
if [ ! -f /etc/openssh/ssh_host_key -o ! -s /etc/openssh/ssh_host_key ]; then
	/usr/bin/openssh-keygen -b 1024 -f /etc/openssh/ssh_host_key -N '' >&2
fi
if test -r /var/run/opensshd.pid
then
	/etc/rc.d/init.d/opensshd restart >&2
fi

%preun
if [ "$1" = 0 ]
then
	/etc/rc.d/init.d/opensshd stop >&2
	/sbin/chkconfig --del opensshd
fi

%files
%defattr(-,root,root)
%doc COPYING.Ylonen ChangeLog ChangeLog.Ylonen OVERVIEW 
%doc README README.openssh
%attr(0755,root,root) /usr/sbin/opensshd
%attr(0755,root,root) /usr/bin/openssh
%attr(0755,root,root) /usr/bin/openssh-agent
%attr(0755,root,root) /usr/bin/openssh-keygen
%attr(0755,root,root) /usr/bin/openssh-add
%attr(0755,root,root) /usr/bin/openscp

# Symlinks
%attr(0755,root,root) /usr/sbin/sshd
%attr(0755,root,root) /usr/bin/ssh
%attr(0755,root,root) /usr/bin/ssh-agent
%attr(0755,root,root) /usr/bin/ssh-keygen
%attr(0755,root,root) /usr/bin/ssh-add
%attr(0755,root,root) /usr/bin/scp

%attr(0755,root,root) /usr/man/man8/opensshd.8
%attr(0755,root,root) /usr/man/man1/openssh.1
%attr(0755,root,root) /usr/man/man1/openssh-agent.1
%attr(0755,root,root) /usr/man/man1/openssh-keygen.1
%attr(0755,root,root) /usr/man/man1/openssh-add.1
%attr(0755,root,root) /usr/man/man1/openscp.1

%attr(0600,root,root) %config /etc/openssh/sshd_config
%attr(0600,root,root) %config /etc/pam.d/opensshd
%attr(0755,root,root) %config /etc/rc.d/init.d/opensshd
%attr(0644,root,root) %config /etc/openssh/ssh_config

