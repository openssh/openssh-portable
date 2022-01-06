OQS-OpenSSH snapshot 2022-01
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2022-01 snapshot release of OQS-OpenSSH, released on January 6, 2022. This release is intended to be used with liboqs version 0.7.1.

What's New
----------

This is the sixth snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 8.6 portable 1.

- Add NTRU and NTRU Prime level 5 KEMs.

---

Detailed changelog
------------------

* added s/ntrup1277 by @baentsch in https://github.com/open-quantum-safe/openssh/pull/112
* adding NTRU hrss1373 and hps40961229 by @baentsch in https://github.com/open-quantum-safe/openssh/pull/113

**Full Changelog**: https://github.com/open-quantum-safe/openssh/compare/OQS-OpenSSH-snapshot-2021-08...OQS-OpenSSH-snapshot-2022-01
