/*	$OpenBSD: rijndael.h,v 1.9 2001/07/30 16:23:30 stevesk Exp $	*/

/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         RIJNDAEL by Joan Daemen and Vincent Rijmen                   */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */

/*
   -----------------------------------------------------------------------
   Copyright (c) 2001 Dr Brian Gladman <brg@gladman.uk.net>, Worcester, UK
   
   TERMS

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   This software is provided 'as is' with no guarantees of correctness or
   fitness for purpose.
   -----------------------------------------------------------------------
*/

#ifndef _RIJNDAEL_H_
#define _RIJNDAEL_H_

#include "config.h"

/* 1. Standard types for AES cryptography source code               */

typedef u_int8_t   u1byte; /* an 8 bit unsigned character type */
typedef u_int16_t  u2byte; /* a 16 bit unsigned integer type   */
typedef u_int32_t  u4byte; /* a 32 bit unsigned integer type   */

typedef int8_t     s1byte; /* an 8 bit signed character type   */
typedef int16_t    s2byte; /* a 16 bit signed integer type     */
typedef int32_t    s4byte; /* a 32 bit signed integer type     */

typedef struct _rijndael_ctx {
	u4byte  k_len;
	int decrypt;
	u4byte  e_key[64];
	u4byte  d_key[64];
} rijndael_ctx;


/* 2. Standard interface for AES cryptographic routines             */

/* These are all based on 32 bit unsigned values and will therefore */
/* require endian conversions for big-endian architectures          */

rijndael_ctx *
rijndael_set_key __P((rijndael_ctx *, const u4byte *, const u4byte, int));
void rijndael_encrypt __P((rijndael_ctx *, const u4byte *, u4byte *));
void rijndael_decrypt __P((rijndael_ctx *, const u4byte *, u4byte *));

#endif /* _RIJNDAEL_H_ */
