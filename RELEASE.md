OQS-OpenSSH snapshot 2022-08
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2022-08 snapshot release of OQS-OpenSSH, released on August 23, 2022. This release is intended to be used with liboqs version 0.7.2.

What's New
----------

This is the seventh snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 8.9 portable 1.

- Update to upstream v8.9p1.
- Remove Rainbow level 1 and SIKE/SIDH.

---

Detailed changelog
------------------

* Use mpint representation for shared_secret when deriving keys in pure-PQ key exchange, and some other bug fixes; fixes #119 by @kevinmkane in https://github.com/open-quantum-safe/openssh/pull/120
* V_8_9_P1 upgrade by @christianpaquin in https://github.com/open-quantum-safe/openssh/pull/121
* bring testing and documentation in line by @baentsch in https://github.com/open-quantum-safe/openssh/pull/123
* remove rainbowI, sike/sidh by @baentsch in https://github.com/open-quantum-safe/openssh/pull/126


**Full Changelog**: https://github.com/open-quantum-safe/openssh/compare/OQS-OpenSSH-snapshot-2022-01...OQS-OpenSSH-snapshot-2022-08
