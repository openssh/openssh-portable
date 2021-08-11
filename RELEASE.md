OQS-OpenSSH snapshot 2021-08
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2021-08 snapshot release of OQS-OpenSSH, released on August 11, 2021. This release is intended to be used with liboqs version 0.7.0.

What's New
----------

This is the fifth snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 8.6 portable 1.

- This is a rewrite of prior versions of OQS-OpenSSH, performed by Goutam Tamvada, Christian Paquin, and Michael Baentsch.
- Uses the updated NIST Round 3 submissions added to liboqs 0.7.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md).
