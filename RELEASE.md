OQS-OpenSSH snapshot 2023-10
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2023-10 snapshot release of OQS-OpenSSH, released on October 21, 2023. This release is intended to be used with liboqs version 0.9.0.

What's New
----------

This is the seventh snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 8.9 portable 1.

- Update algorithm list in line with `liboqs` v0.9.0.

---

Detailed changelog
------------------

* Update IDs to reflect updated McEliece in liboqs v0.9.0 in https://github.com/open-quantum-safe/openssh/pull/148

**Full Changelog**: https://github.com/open-quantum-safe/openssh/compare/OQS-OpenSSH-snapshot-2023-06...OQS-OpenSSH-snapshot-2023-10
