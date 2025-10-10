/*
 * Copyright (C) 2024 Tianjia Zhang
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SM3_H_
#define _SM3_H_

#ifndef WITH_OPENSSL

#define SM3_BLOCK_LENGTH  64
#define SM3_DIGEST_LENGTH 32

typedef struct SM3Context {
    u_int32_t state[SM3_DIGEST_LENGTH / 4];
    u_int64_t count;
    u_int8_t buffer[SM3_BLOCK_LENGTH];
} SM3_CTX;

void SM3Init(SM3_CTX *);
void SM3Update(SM3_CTX *, const u_int8_t *, size_t);
void SM3Final(u_int8_t[SM3_DIGEST_LENGTH], SM3_CTX *);
void SM3Buf(const u_int8_t *, size_t, u_int8_t[SM3_DIGEST_LENGTH]);

#endif /* !WITH_OPENSSL */

#endif /* !_SM3_H_ */
