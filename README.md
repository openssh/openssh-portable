[![Build status image](https://circleci.com/gh/open-quantum-safe/openssh/tree/OQS-master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssh/tree/OQS-master)

OQS-OpenSSH
==================================

[OpenSSH](https://openssh.org/) is an open-source implementation of the Secure Shell protocol.  ([View the original README](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README.original.md).)

OQS-OpenSSH is a fork of OpenSSH that adds quantum-safe key exchange and signature algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSH project.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Algorithms](#supported-algorithms)
- [Quickstart](#quickstart)
  * [Building OQS-OpenSSH](#building-oqs-openssh)
  * [Running OQS-OpenSSH](#running-oqs-openssh)
- [Contributing](#contributing)
- [License](#license)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-OpenSSH** is a fork of OpenSSH that adds quantum-safe cryptography to enable its use and evaluation in the SSH protocol.

Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

This fork is currently based on OpenSSH version **8.4** (Git tag V_8_4_P1); release notes can be found [here](RELEASE.md). **IT IS AT AN EXPERIMENTAL STAGE**, and has not received the same level of auditing and analysis that OpenSSH has received. See the [Limitations and Security](#limitations-and-security) section below for more information.

**WE DO NOT RECOMMEND RELYING ON THIS FORK TO PROTECT SENSITIVE DATA.**

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

This fork implements the [draft-kampanakis-curdle-pq-ssh-00](https://datatracker.ietf.org/doc/draft-kampanakis-curdle-pq-ssh/) IETF draft for hybrid key exchange algorithms.

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it can still be used in the fork through [either one of two ways](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqs-default-sha256` (see [here](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork) for what this denotes)
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_START -->
- **FrodoKEM**: `frodokem-640-aes-sha256`, `frodokem-976-aes-sha384`, `frodokem-1344-aes-sha512`
- **SIKE**: `sike-p434-sha256`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END -->

For each `<KEX>` listed above, the following hybrid algorithms are made available as follows:

- If `<KEX>` has L1 security, the method `ecdh-nistp256-<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P256 curve
- If `<KEX>` has L3 security, the method `ecdh-nistp384-<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P384 curve
- If `<KEX>` has L5 security, the method `ecdh-nistp521-<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P521 curve

Note that algorithms marked with a dagger (†) have large stack usage and may cause failures when run on threads or in constrained environments.

#### Digital Signature

The following digital signature algorithms from liboqs are supported (assuming they have been enabled in liboqs). Note that only L1 signature and all **Rainbow** variants are enabled by default, and should you wish to enable additional variants, consult [the "Code Generation" section of the documentation in the wiki](https://github.com/open-quantum-safe/openssh/wiki/Using-liboqs-supported-algorithms-in-the-for://github.com/open-quantum-safe/openssh/wiki/Using-liboqs-supported-algorithms-in-the-fork#code-generation).

- `oqsdefault` (see [here](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork) for what this denotes)
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START -->
- **Dilithium**: `dilithium2`, `dilithium3`, `dilithium5`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END -->

The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with a traditional digital signature algorithm (`<SIG>` is any one of the algorithms listed above):

- if `<SIG>` has L1 security, then the fork provides the methods `rsa3072-<SIG>` and `ecdsa-nistp256-<SIG>`, which combine `<SIG>` with RSA3072 and with ECDSA using NIST's P256 curve respectively.
- if `<SIG>` has L3 security, the fork provides the method `ecdsa-nistp384-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P384 curve.
- if `<SIG>` has L5 security, the fork provides the method `ecdsa-nistp521-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P521 curve.

## Quickstart

The steps below have been confirmed to work on macOS 10.14 (clang 10.0.0) and Ubuntu 18.04.1 Bionic (gcc-7).

### Building OQS-OpenSSH

### Step 0: Install dependencies

On **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake cmake gcc libtool libssl-dev make ninja-build zlib1g-dev

On **Linux**, you also may need to do the following:

- You may need to create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

- You may need to create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

On **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake cmake libtool ninja openssl@1.1 wget

### Step 1: Build and install liboqs

The following instructions install liboqs into a subdirectory inside the OpenSSH source. If `<OPENSSH_ROOT>` is the root of the OpenSSH source:

```
git clone --branch master --single-branch --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake .. -GNinja -DOQS_ENABLE_SIG_PICNIC=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=<OPENSSH_ROOT>/oqs
ninja
ninja install
```

Building liboqs requires your system to have OpenSSL 1.1.1 or higher already installed. It will automatically be detected if it in a standard location, such as `/usr` or `/usr/local/opt/openssl@1.1` (for brew on macOS).  Otherwise, you may need to specify it with `-DOPENSSL_ROOT_DIR=<path-to-system-openssl-dir>` added to the `cmake` command.

### Step 2: Build the fork

In `<OPENSSH_ROOT>`, first run:

```
export LIBOQS_INSTALL=<path-to-liboqs>
export OPENSSH_INSTALL=<path-to-install-openssh>
autoreconf
```

Then, run the following:

	./configure --with-ssl-dir=<path-to-openssl>/include \
	            --with-ldflags=-L<path-to-openssl>/lib   \
	            --with-libs=-lm                          \
	            --prefix=$OPENSSH_INSTALL                \
	            --sysconfdir=$OPENSSH_INSTALL            \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

To test the build, run:

	make tests

To run OQS-specific tests of all the post-quantum key-exchanges:

```
python3 -m nose --rednose --verbose
```

To run OQS-specific tests of all combinations of post-quantum key-exchange and authentication algorithms:

```
env WITH_PQAUTH=true python3 -m nose --rednose --verbose
```

### Running OQS-OpenSSH

The following instructions explain how to establish an SSH connection that uses quantum-safe key exchange and authentication.

#### Generating quantum-safe authentication keys

To setup quantum-safe authentication, the server (and optionally, the client) need to generate quantum-safe keys. In what follows, `<SIG>` is one of the quantum-safe digital signature algorithms listed in [Supported Algorithms](#supported-algorithms) section above.

The server generates its key files with the right permissions, and then generates its key pair:

	mkdir ~/ssh_server/
	chmod 700 ~/ssh_server/
	touch ~/ssh_server/authorized_keys
	chmod 600 ~/ssh_server/authorized_keys
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_server/id_<SIG>

To enable client-side public-key authentication, the client generates its key pair:

	mkdir ~/ssh_client/
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_client/id_<SIG>

The server then adds the client's public key to its authorized keys

	cat ~/ssh_client/id_<SIG>.pub >> ~/ssh_server/authorized_keys

#### Establishing a quantum-safe SSH connection

In one terminal, run a server:

	<path-to-openssh>/sbin/sshd -p 2222 -d \
	                            -o KexAlgorithms=<KEX> \
	                            -o AuthorizedKeysFile=<absolute-path-to>/ssh_server/authorized_keys \
	                            -o HostKeyAlgorithms=ssh-<SIG> \
	                            -o PubkeyAcceptedKeyTypes=ssh-<SIG> \
	                            -h <absolute-path-to>/ssh_server/id_<SIG>]

`<KEX>` and `<SIG>` are respectively one of the key exchange and signature (PQ-only or hybrid) algorithms listed in the [Supported Algorithms](#supported-algorithms) section above.

The `-o` options can also be added to the server/client configuration file instead of being specified on the command line.

The server automatically supports all available hybrid and PQ-only key exchange algorithms.  `sudo` is required on Linux so that sshd can read the shadow password file.

In another terminal, run a client(the arguments between `[...]` can be omitted if only classical authentication is required):

	<path-to-openssh>/bin/ssh -p 2222 localhost \
	                          -o KexAlgorithms=<KEX> \
	                          -o HostKeyAlgorithms=ssh-<SIG>\
	                          -o PubkeyAcceptedKeyTypes=ssh-<SIG> \
	                          -o StrictHostKeyChecking=no \
	                          -i ~/ssh_client/id_<SIG>

The `StrictHostKeyChecking` option is used to allow trusting the newly generated server key; alternatively, the key could be added manually to the client's trusted keys.

## Contributing

Contributions are gratefully welcomed. See our [Contributing Guide](https://github.com/open-quantum-safe/openssh-portable/wiki/Contributing-Guide) for more details.

## License

This fork is released under the same license(s) as Portable OpenSSH. More information can be found in the [LICENSE](LICENSE) file.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork of OpenSSH include:

- Eric Crockett (Amazon Web Services)
- Ben Davies (University of Waterloo)
- Torben Hansen (Amazon Web Services and Royal Holloway, University of London)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)
- Goutam Tamvada (University of Waterloo)

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
