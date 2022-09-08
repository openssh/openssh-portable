# HPNSSH: Based on Portable OpenSSH

Starting with version HPN17v0 there will be significant changes to the naming convention used for executables and installation locations. The last version that does not include these changes is HPN16v1 corresponding to the HPN-8_8_P1 tag on the master branch.

HPNSSH is a variant of OpenSSH. It a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client ``hpnssh`` and server ``hpnsshd``, file transfer utilities ``hpnscp`` and ``hpnsftp`` as well as tools for key generation (``hpnssh-keygen``), run-time key storage (``hpnssh-agent``) and a number of supporting programs. It includes numerous performance and functionality enhancements focused on high performance networks and computing envrironments. Complete information can be found in the HPN-README file.

It is fully compatible with all compliant implementations of the SSH protocol and OpenSSH in particular.

This version of HPNSSH is significant departure in terms of naming executables and installation locations. Specifically, all executables are now prefixed with ``hpn``. So ``ssh`` becomes ``hpnssh`` and ``scp`` is now ``hpnscp``. Configuation files and host keys can now be found in ``/etc/hpnssh``. By default ``hpnsshd`` now runs on port 2222 but this is configurable. This change was made in order to prevent installations of hpnssh, particularly from package distributions, from interfering with default installations of OpenSSH. HPNSSH is backwards compatible with all versions of OpenSSH including configuration files, keys, and run time options. Additionally, the client will, by default attempt to connect to port 2222 but will automatically fall back to port 22. This is also user configurable.

HPNSSH is based on OpenSSH portable. This is a port of OpenBSD's [OpenSSH](https://openssh.com) to most Unix-like operating systems, including Linux, OS X and Cygwin. Portable OpenSSH polyfills OpenBSD APIs that are not available elsewhere, adds sshd sandboxing for more operating systems and includes support for OS-native authentication and auditing (e.g. using PAM).

This document will be changing over time to reflect new changes and features. This document is built off of the OpenSSH README.md

## Documentation

The official documentation for OpenSSH are the man pages for each tool:

* [ssh(1)](https://man.openbsd.org/ssh.1)
* [sshd(8)](https://man.openbsd.org/sshd.8)
* [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [scp(1)](https://man.openbsd.org/scp.1)
* [sftp(1)](https://man.openbsd.org/sftp.1)
* [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Building HPNSSH

### Dependencies

HPNSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used, but OpenSSH may be built without it supporting a subset of crypto algorithms.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies. Also, certain platforms and build-time options may require additional dependencies; see README.platform for details.

### Building a release

Releases include a pre-built copy of the ``configure`` script and may be built using:

```
tar zxvf hpnssh-X.YpZ.tar.gz
cd hpnssh
./configure # [options]
make && make tests
```

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.

### Building from git

If building from git, you'll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the ``configure`` script. The following commands will check out and build portable OpenSSH from git:

```
git clone https://github.com/rapier1/openssh-portable
cd openssh-portable
autoreconf
./configure
make && make tests
```

### Build-time Customisation

There are many build-time customisation options available. All Autoconf destination path flags (e.g. ``--prefix``) are supported (and are usually required if you want to install OpenSSH).

For a full list of available flags, run ``configure --help`` but a few of the more frequently-used ones are described below. Some of these flags will require additional libraries and/or headers be installed.

Flag | Meaning
--- | ---
``--with-pam`` | Enable [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) support. [OpenPAM](https://www.openpam.org/), [Linux PAM](http://www.linux-pam.org/) and Solaris PAM are supported.
``--with-libedit`` | Enable [libedit](https://www.thrysoee.dk/editline/) support for sftp.
``--with-kerberos5`` | Enable Kerberos/GSSAPI support. Both [Heimdal](https://www.h5l.org/) and [MIT](https://web.mit.edu/kerberos/) Kerberos implementations are supported.
``--with-selinux`` | Enable [SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) support.
``--with-security-key-builtin`` | Include built-in support for U2F/FIDO2 security keys. This requires [libfido2](https://github.com/Yubico/libfido2) be installed.
