/*
 * rijndael-alg-fst.h   v2.4   April '2000
 * rijndael-api-fst.h   v2.4   April '2000
 *
 * Optimised ANSI C code
 *
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define RIJNDAEL_MAXKC		(256/32)
#define RIJNDAEL_MAXROUNDS	14

#define	RIJNDAEL_ENCRYPT	0
#define	RIJNDAEL_DECRYPT	1

typedef struct {
	int ROUNDS;		/* key-length-dependent number of rounds */
	u_int8_t keySched[RIJNDAEL_MAXROUNDS+1][4][4];
} rijndael_key;

int rijndael_encrypt(rijndael_key *key, u_int8_t a[16], u_int8_t b[16]);
int rijndael_decrypt(rijndael_key *key, u_int8_t a[16], u_int8_t b[16]);
int rijndael_makekey(rijndael_key *key, int direction, int keyLen, u_int8_t *keyMaterial);

#endif
