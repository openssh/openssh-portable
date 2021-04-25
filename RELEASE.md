OQS-OpenSSH snapshot 2020-08
============================

** TO-DO: update for 8.x branch (this is the 7.9 README) **

*** TODO: to update for next release ***

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2020-08 snapshot release of OQS-OpenSSH, released on August 11, 2020. Its release page on GitHub is https://github.com/open-quantum-safe/openssh/releases/tag/OQS-OpenSSH-snapshot-2020-08. This release is intended to be used with liboqs version 0.4.0.

What's New
----------

This is the fourth snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 8.4 portable 1.

- Uses the updated NIST Round 2 submissions added to liboqs 0.4.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/master/RELEASE.md).

Deprecations
------------

As a result of NIST's announcement of Round 3 of the Post-Quantum Cryptography Standardization Project, this is the last release of OQS-OpenSSH that contain algorithms from Round 2 that are not Round 3 finalists or alternate candidates. Those algorithms will be removed in the next release. The algorithms in question are: NewHope, ThreeBears, MQDSS, and qTesla. These algorithms are considered deprecated within OQS-OpenSSH will receive no updates after this release.
