# getting started
This is a fork of openssh server to create a secure tunnel between users, devices etc..
This version implements new authentication protocols like oauth2,SSO, active directory etc...


## prepare

```bash
sudo apt install zlib1g-dev
sudo apt install libssl-dev
sudo apt install libpam0g-dev


```

## doc
you can open documents under doc folder with [app.diagrams.net](https://app.diagrams.net)
## compile

```bash
aclocal
autoconf
autoreconf
./configure --prefix=$(pwd)/build --disable-strip CFLAGS="-W -O0 -g -ggdb -DFERRUM_DEBUG -DFERRUM -DFERRUM_PROD -I$(pwd)/external/libs/include" CXXFLAGS="-W -O0 -g -ggdb -DFERRUM_DEBUG -DFERRUM -DFERRUM_PROD" LDFLAGS="-L$(pwd)/external/libs/lib -lhiredis" --with-pam
# compile with NO_SSH_LASTLOG
make
make install

FERRUM_DEBUG flags is for support SSH with none cipher

```

## run

edit ./build/etc/sshd_config and replace port to 3333
> sudo $(pwd)/build/sbin/sshd -D  -f $(pwd)/build/etc/sshd_config

for log 
> tail -f /var/log/auth.log

for client  connection
> ssh user@localhost -p3333


## ssh server run
> REDIS_HOST=192.168.88.253 LOGIN_URL=http://localhost:4200/login $(pwd)/sshd -D  -f ../etc/sshd_config

## ssh client run
> ./ssh -c none -N -F ../etc/ssh_config -w any  sshd@192.168.88.243 -p3333
## sample sshd_config


```html

#	$OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin:/work/projects/ferrum/secure.server/build/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.
Port 3333
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

HostKey /root/build/etc/ssh_host_rsa_key
#HostKey /work/projects/ferrum/secure.server/build/etc/ssh_host_ecdsa_key
#HostKey /work/projects/ferrum/secure.server/build/etc/ssh_host_ed25519_key

# Ciphers and keying
Ciphers aes128-cbc,none
#RekeyLimit default none

# Logging
SyslogFacility AUTH
LogLevel DEBUG3

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys
#UsePrivilegeSeparation yes
#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /work/projects/ferrum/secure.server/build/etc/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
IgnoreUserKnownHosts yes
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no  #no
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
KbdInteractiveAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

AllowAgentForwarding no
# disable local and remote forward
AllowTcpForwarding no
# disable remote forward
GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
X11UseLocalhost no
PermitTTY no #this must be no
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
Compression no #delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
PidFile /tmp/sshd.pid
#MaxStartups 10:30:100
PermitTunnel yes
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
#Subsystem	sftp	/work/projects/ferrum/secure.server/build/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
### disables remote and local forwardings 
DisableForwarding yes

```
