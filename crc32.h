/*
 *
 * crc32.h
 *
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 *
 * Copyright (c) 1992 Tatu Ylonen, Espoo, Finland
 *                    All rights reserved
 *
 * Created: Tue Feb 11 14:37:27 1992 ylo
 *
 * Functions for computing 32-bit CRC.
 *
 */

/* RCSID("$OpenBSD: crc32.h,v 1.7 2000/08/19 21:29:40 deraadt Exp $"); */

#ifndef CRC32_H
#define CRC32_H

/*
 * This computes a 32 bit CRC of the data in the buffer, and returns the CRC.
 * The polynomial used is 0xedb88320.
 */
unsigned int ssh_crc32(const unsigned char *buf, unsigned int len);

#endif				/* CRC32_H */
