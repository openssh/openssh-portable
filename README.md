[![CircleCI](https://circleci.com/gh/open-quantum-safe/openssh/tree/OQS-v8.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssh/tree/OQS-v8)

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

This fork is currently based on OpenSSH version **8.9** (Git tag V_8_9_P1); release notes can be found [here](RELEASE.md). **IT IS AT AN EXPERIMENTAL STAGE**, and has not received the same level of auditing and analysis that OpenSSH has received. See the [Limitations and Security](#limitations-and-security) section below for more information.

**WE DO NOT RECOMMEND RELYING ON THIS FORK TO PROTECT SENSITIVE DATA.**

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt) for the full disclaimer.
Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used, but OpenSSH may be built without it supporting a subset of crypto algorithms.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies. Also, certain platforms and build-time options may require additional dependencies; see README.platform for details.

This fork implements the [draft-kampanakis-curdle-ssh-pq-ke](https://datatracker.ietf.org/doc/draft-kampanakis-curdle-ssh-pq-ke/) IETF draft for hybrid key exchange algorithms.

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it can still be used in the fork through [either one of two ways](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_START -->
- **BIKE**: `bike-l1-sha512`, `bike-l3-sha512`
- **ClassicMcEliece**: `classic-mceliece-348864-sha256`, `classic-mceliece-348864f-sha256`, `classic-mceliece-460896-sha512`, `classic-mceliece-460896f-sha512`, `classic-mceliece-6688128-sha512`, `classic-mceliece-6688128f-sha512`, `classic-mceliece-6960119-sha512`, `classic-mceliece-6960119f-sha512`, `classic-mceliece-8192128-sha512`, `classic-mceliece-8192128f-sha512`
- **FrodoKEM**: `frodokem-640-aes-sha256`, `frodokem-976-aes-sha384`, `frodokem-1344-aes-sha512`, `frodokem-640-shake-sha256`, `frodokem-976-shake-sha384`, `frodokem-1344-shake-sha512`
- **HQC**: `hqc-128-sha256`, `hqc-192-sha384`, `hqc-256-sha512`†
- **Kyber**: `kyber-512-sha256`, `kyber-768-sha384`, `kyber-1024-sha512`, `kyber-512-90s-sha256`, `kyber-768-90s-sha384`, `kyber-1024-90s-sha512`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END -->

The following hybrid algorithms are made available:

<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_HYBRID_KEXS_START -->
- **BIKE**: `ecdh-nistp256-bike-l1r3-sha512@openquantumsafe.org` `ecdh-nistp384-bike-l3r3-sha512@openquantumsafe.org`
- **ClassicMcEliece**: `ecdh-nistp256-classic-mceliece-348864r3-sha256@openquantumsafe.org` `ecdh-nistp256-classic-mceliece-348864fr3-sha256@openquantumsafe.org` `ecdh-nistp384-classic-mceliece-460896r3-sha512@openquantumsafe.org` `ecdh-nistp384-classic-mceliece-460896fr3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-6688128r3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-6688128fr3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-6960119r3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-6960119fr3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-8192128r3-sha512@openquantumsafe.org` `ecdh-nistp521-classic-mceliece-8192128fr3-sha512@openquantumsafe.org`
- **FrodoKEM**: `ecdh-nistp256-frodokem-640-aesr2-sha256@openquantumsafe.org` `ecdh-nistp384-frodokem-976-aesr2-sha384@openquantumsafe.org` `ecdh-nistp521-frodokem-1344-aesr2-sha512@openquantumsafe.org` `ecdh-nistp256-frodokem-640-shaker2-sha256@openquantumsafe.org` `ecdh-nistp384-frodokem-976-shaker2-sha384@openquantumsafe.org` `ecdh-nistp521-frodokem-1344-shaker2-sha512@openquantumsafe.org`
- **HQC**: `ecdh-nistp256-hqc-128r3-sha256@openquantumsafe.org` `ecdh-nistp384-hqc-192r3-sha384@openquantumsafe.org` `ecdh-nistp521-hqc-256r3-sha512@openquantumsafe.org`
- **Kyber**: `ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org` `ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org` `ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org` `ecdh-nistp256-kyber-512-90sr3-sha256@openquantumsafe.org` `ecdh-nistp384-kyber-768-90sr3-sha384@openquantumsafe.org` `ecdh-nistp521-kyber-1024-90sr3-sha512@openquantumsafe.org`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_HYBRID_KEXS_END -->

Note that algorithms marked with a dagger (†) have large stack usage and may cause failures when run on threads or in constrained environments. For example, McEliece require building `oqs-openssh` with a large(r) stack provision than is default: Adding `LDFLAGS="-Wl,--stack,20000000"` to [the `./configure` command below](#step-2-build-the-fork) is required to allow cygwin-based testing to pass.

#### Digital Signature

The following digital signature algorithms from liboqs are supported (assuming they have been enabled in liboqs). Note that only select L3 signature variants are enabled by default. In general, algorithms that are enabled by default are marked with an asterisk, and should you wish to enable additional variants, consult [the "Code Generation" section of the documentation in the wiki](https://github.com/open-quantum-safe/openssh/wiki/Using-liboqs-supported-algorithms-in-the-fork#code-generation).

<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START -->
- **Dilithium**: `dilithium2`\*, `dilithium3`\*, `dilithium5`\*, `dilithium2aes`, `dilithium3aes`, `dilithium5aes`
- **Falcon**: `falcon512`\*, `falcon1024`\*
- **SPHINCS**: `sphincsharaka128frobust`, `sphincsharaka128fsimple`\*, `sphincsharaka128srobust`, `sphincsharaka128ssimple`, `sphincssha256128frobust`, `sphincssha256128srobust`, `sphincssha256128fsimple`\*, `sphincssha256128ssimple`, `sphincsshake256128frobust`, `sphincsshake256128srobust`, `sphincsshake256128fsimple`, `sphincsshake256128ssimple`, `sphincsharaka192frobust`, `sphincsharaka192srobust`, `sphincsharaka192fsimple`, `sphincsharaka192ssimple`, `sphincssha256192frobust`, `sphincssha256192srobust`\*, `sphincssha256192fsimple`, `sphincssha256192ssimple`, `sphincsshake256192frobust`, `sphincsshake256192srobust`, `sphincsshake256192fsimple`, `sphincsshake256192ssimple`, `sphincsharaka256frobust`, `sphincsharaka256srobust`, `sphincsharaka256fsimple`, `sphincsharaka256ssimple`, `sphincssha256256frobust`, `sphincssha256256srobust`, `sphincssha256256fsimple`\*, `sphincssha256256ssimple`, `sphincsshake256256frobust`, `sphincsshake256256srobust`, `sphincsshake256256fsimple`, `sphincsshake256256ssimple`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END -->


The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with a traditional digital signature algorithm (`<SIG>` is any one of the algorithms listed above):

- if `<SIG>` has L1 security, then the fork provides the methods `rsa3072-<SIG>` and `ecdsa-nistp256-<SIG>`, which combine `<SIG>` with RSA3072 and with ECDSA using NIST's P256 curve respectively.
- if `<SIG>` has L3 security, the fork provides the method `ecdsa-nistp384-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P384 curve.
- if `<SIG>` has L5 security, the fork provides the method `ecdsa-nistp521-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P521 curve.

## Quickstart

The steps below have been confirmed to work on Ubuntu 20.04.1 Focal

### Building OQS-OpenSSH

### Step 0: Install dependencies

On **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake cmake gcc libtool libssl-dev make ninja-build zlib1g-dev

On **Linux**, you also may need to do the following:

- Create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

- Create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

### Step 1: Build and install liboqs

The following instructions install liboqs into a subdirectory inside the OpenSSH source.

```
./oqs-scripts/clone_liboqs.sh
./oqs-scripts/build_liboqs.sh
```

Building liboqs requires your system to have OpenSSL 1.1.1 or higher already installed. It will automatically be detected if it is under `/usr` or another standard location.  Otherwise, you may need to specify it with `-DOPENSSL_ROOT_DIR=<path-to-system-openssl-dir>` added to the `cmake` command.

### Step 2: Build the fork

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.

Run the following:

```
env OPENSSL_SYS_DIR=<PATH_TO_OPENSSL> ./oqs-scripts/build_openssh.sh
```

`OPENSSL_SYS_DIR` does not have to be specified if OpenSSL is present under `/usr`.

As not all tests in the stock regression suite pass, run `oqs-test/run_tests.sh` instead of simply executing `make tests` to ensure the build was successful.

To execute a connection test with a randomly chosen key-exchange and signature algorithm, run `python3 oqs-test/try_connection.py`. If it is desired that each such combination be tested (exactly once), run `python3 oqs-test/try_connection.py all`. Be aware that the latter can take a long time due to the number of algorithm combinations available.

### Running OQS-OpenSSH

The following instructions explain how to establish an SSH connection that uses quantum-safe key exchange and authentication.

#### Generating quantum-safe authentication keys

To setup quantum-safe authentication, the server (and optionally, the client) need to generate quantum-safe keys. To generate keys for all the OQS algorithms supported by fork, simply run `make tests -e LTESTS=""`.

Keys for a particular `<SIG>` also be generated using the `ssh-keygen` command as follows:

`<OPENSSH_SRC>/ssh-keygen -t ssh-<SIG> -f ~/ssh_client/id_<SIG>`

#### Establishing a quantum-safe SSH connection

Let `<OPENSSH_SRC>` denote the absolute path to the directory in which this source is present.

In one terminal, run the ssh server:

	<OPENSSH_SRC>/sshd -D \
	                   -f <OPENSSH_SRC>/regress/sshd_config \
	                   -o KexAlgorithms=<KEX> \
	                   -o HostKeyAlgorithms=ssh-<SIG> \
	                   -o PubkeyAcceptedKeyTypes=ssh-<SIG> \
	                   -h <OPENSSH_SRC>/regress/host.ssh-<SIG>

`<KEX>` and `<SIG>` are respectively one of the key exchange and signature (PQ-only or hybrid) algorithms listed in the [Supported Algorithms](#supported-algorithms) section above.

The `-o` options can also be added to the server/client configuration file instead of being specified on the command line.

In another terminal, run the ssh client:

	<OPENSSH_SRC>/ssh -F <OPENSSH_SRC>/regress/ssh_config \
	                  -o KexAlgorithms=<KEX> \
	                  -o HostKeyAlgorithms=ssh-<SIG>\
	                  -o PubkeyAcceptedKeyTypes=ssh-<SIG> \
	                  -o PasswordAuthentication=no \
	                  -i regress/ssh-<SIG> \
	                  somehost true

The `PasswordAuthentication` option is used to ensure the test server does not fall back to password authentication if public key authentication fails for some reason.

The -o options can also be added to the `regress/{ssh|sshd}_config` client/server configuration files instead of being specified on the command line.

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
- Michael Baentsch

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
