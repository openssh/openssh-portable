/*
 * rijndael-alg-fst.c   v2.4   April '2000
 * rijndael-alg-api.c   v2.4   April '2000
 *
 * Optimised ANSI C code
 *
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen, K.U.Leuven
 *          v2.3: Paulo Barreto
 *          v2.4: Vincent Rijmen, K.U.Leuven
 *
 * This code is placed in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "config.h"
#include "rijndael.h"
#include "rijndael_boxes.h"

int
rijndael_keysched(u_int8_t k[RIJNDAEL_MAXKC][4],
    u_int8_t W[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS)
{
	/* Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */ 
	int j, r, t, rconpointer = 0;
	u_int8_t tk[RIJNDAEL_MAXKC][4];
	int KC = ROUNDS - 6;

	for (j = KC-1; j >= 0; j--) {
		*((u_int32_t*)tk[j]) = *((u_int32_t*)k[j]);
	}
	r = 0;
	t = 0;
	/* copy values into round key array */
	for (j = 0; (j < KC) && (r < ROUNDS + 1); ) {
		for (; (j < KC) && (t < 4); j++, t++) {
			*((u_int32_t*)W[r][t]) = *((u_int32_t*)tk[j]);
		}
		if (t == 4) {
			r++;
			t = 0;
		}
	}
		
	while (r < ROUNDS + 1) { /* while not enough round key material calculated */
		/* calculate new values */
		tk[0][0] ^= S[tk[KC-1][1]];
		tk[0][1] ^= S[tk[KC-1][2]];
		tk[0][2] ^= S[tk[KC-1][3]];
		tk[0][3] ^= S[tk[KC-1][0]];
		tk[0][0] ^= rcon[rconpointer++];

		if (KC != 8) {
			for (j = 1; j < KC; j++) {
				*((u_int32_t*)tk[j]) ^= *((u_int32_t*)tk[j-1]);
			}
		} else {
			for (j = 1; j < KC/2; j++) {
				*((u_int32_t*)tk[j]) ^= *((u_int32_t*)tk[j-1]);
			}
			tk[KC/2][0] ^= S[tk[KC/2 - 1][0]];
			tk[KC/2][1] ^= S[tk[KC/2 - 1][1]];
			tk[KC/2][2] ^= S[tk[KC/2 - 1][2]];
			tk[KC/2][3] ^= S[tk[KC/2 - 1][3]];
			for (j = KC/2 + 1; j < KC; j++) {
				*((u_int32_t*)tk[j]) ^= *((u_int32_t*)tk[j-1]);
			}
		}
		/* copy values into round key array */
		for (j = 0; (j < KC) && (r < ROUNDS + 1); ) {
			for (; (j < KC) && (t < 4); j++, t++) {
				*((u_int32_t*)W[r][t]) = *((u_int32_t*)tk[j]);
			}
			if (t == 4) {
				r++;
				t = 0;
			}
		}
	}		
	return 0;
}

int
rijndael_key_enc_to_dec(u_int8_t W[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS)
{
	int r;
	u_int8_t *w;

	for (r = 1; r < ROUNDS; r++) {
		w = W[r][0];
		*((u_int32_t*)w) = *((u_int32_t*)U1[w[0]])
				 ^ *((u_int32_t*)U2[w[1]])
				 ^ *((u_int32_t*)U3[w[2]])
				 ^ *((u_int32_t*)U4[w[3]]);

		w = W[r][1];
		*((u_int32_t*)w) = *((u_int32_t*)U1[w[0]])
				 ^ *((u_int32_t*)U2[w[1]])
				 ^ *((u_int32_t*)U3[w[2]])
				 ^ *((u_int32_t*)U4[w[3]]);

		w = W[r][2];
		*((u_int32_t*)w) = *((u_int32_t*)U1[w[0]])
				 ^ *((u_int32_t*)U2[w[1]])
				 ^ *((u_int32_t*)U3[w[2]])
				 ^ *((u_int32_t*)U4[w[3]]);

		w = W[r][3];
		*((u_int32_t*)w) = *((u_int32_t*)U1[w[0]])
				 ^ *((u_int32_t*)U2[w[1]])
				 ^ *((u_int32_t*)U3[w[2]])
				 ^ *((u_int32_t*)U4[w[3]]);
	}
	return 0;
}	

/**
 * Encrypt a single block. 
 */
int
rijndael_encrypt(rijndael_key *key, u_int8_t a[16], u_int8_t b[16])
{
	u_int8_t (*rk)[4][4] = key->keySched;
	int ROUNDS = key->ROUNDS;
	int r;
	u_int8_t temp[4][4];

	*((u_int32_t*)temp[0]) = *((u_int32_t*)(a   )) ^ *((u_int32_t*)rk[0][0]);
	*((u_int32_t*)temp[1]) = *((u_int32_t*)(a+ 4)) ^ *((u_int32_t*)rk[0][1]);
	*((u_int32_t*)temp[2]) = *((u_int32_t*)(a+ 8)) ^ *((u_int32_t*)rk[0][2]);
	*((u_int32_t*)temp[3]) = *((u_int32_t*)(a+12)) ^ *((u_int32_t*)rk[0][3]);
	*((u_int32_t*)(b    )) = *((u_int32_t*)T1[temp[0][0]])
			       ^ *((u_int32_t*)T2[temp[1][1]])
			       ^ *((u_int32_t*)T3[temp[2][2]]) 
			       ^ *((u_int32_t*)T4[temp[3][3]]);
	*((u_int32_t*)(b + 4)) = *((u_int32_t*)T1[temp[1][0]])
			       ^ *((u_int32_t*)T2[temp[2][1]])
			       ^ *((u_int32_t*)T3[temp[3][2]]) 
			       ^ *((u_int32_t*)T4[temp[0][3]]);
	*((u_int32_t*)(b + 8)) = *((u_int32_t*)T1[temp[2][0]])
			       ^ *((u_int32_t*)T2[temp[3][1]])
			       ^ *((u_int32_t*)T3[temp[0][2]]) 
			       ^ *((u_int32_t*)T4[temp[1][3]]);
	*((u_int32_t*)(b +12)) = *((u_int32_t*)T1[temp[3][0]])
			       ^ *((u_int32_t*)T2[temp[0][1]])
			       ^ *((u_int32_t*)T3[temp[1][2]]) 
			       ^ *((u_int32_t*)T4[temp[2][3]]);
	for (r = 1; r < ROUNDS-1; r++) {
		*((u_int32_t*)temp[0]) = *((u_int32_t*)(b   )) ^ *((u_int32_t*)rk[r][0]);
		*((u_int32_t*)temp[1]) = *((u_int32_t*)(b+ 4)) ^ *((u_int32_t*)rk[r][1]);
		*((u_int32_t*)temp[2]) = *((u_int32_t*)(b+ 8)) ^ *((u_int32_t*)rk[r][2]);
		*((u_int32_t*)temp[3]) = *((u_int32_t*)(b+12)) ^ *((u_int32_t*)rk[r][3]);

		*((u_int32_t*)(b    )) = *((u_int32_t*)T1[temp[0][0]])
				       ^ *((u_int32_t*)T2[temp[1][1]])
				       ^ *((u_int32_t*)T3[temp[2][2]]) 
				       ^ *((u_int32_t*)T4[temp[3][3]]);
		*((u_int32_t*)(b + 4)) = *((u_int32_t*)T1[temp[1][0]])
				       ^ *((u_int32_t*)T2[temp[2][1]])
				       ^ *((u_int32_t*)T3[temp[3][2]]) 
				       ^ *((u_int32_t*)T4[temp[0][3]]);
		*((u_int32_t*)(b + 8)) = *((u_int32_t*)T1[temp[2][0]])
				       ^ *((u_int32_t*)T2[temp[3][1]])
				       ^ *((u_int32_t*)T3[temp[0][2]]) 
				       ^ *((u_int32_t*)T4[temp[1][3]]);
		*((u_int32_t*)(b +12)) = *((u_int32_t*)T1[temp[3][0]])
				       ^ *((u_int32_t*)T2[temp[0][1]])
				       ^ *((u_int32_t*)T3[temp[1][2]]) 
				       ^ *((u_int32_t*)T4[temp[2][3]]);
	}
	/* last round is special */   
	*((u_int32_t*)temp[0]) = *((u_int32_t*)(b   )) ^ *((u_int32_t*)rk[ROUNDS-1][0]);
	*((u_int32_t*)temp[1]) = *((u_int32_t*)(b+ 4)) ^ *((u_int32_t*)rk[ROUNDS-1][1]);
	*((u_int32_t*)temp[2]) = *((u_int32_t*)(b+ 8)) ^ *((u_int32_t*)rk[ROUNDS-1][2]);
	*((u_int32_t*)temp[3]) = *((u_int32_t*)(b+12)) ^ *((u_int32_t*)rk[ROUNDS-1][3]);
	b[ 0] = T1[temp[0][0]][1];
	b[ 1] = T1[temp[1][1]][1];
	b[ 2] = T1[temp[2][2]][1];
	b[ 3] = T1[temp[3][3]][1];
	b[ 4] = T1[temp[1][0]][1];
	b[ 5] = T1[temp[2][1]][1];
	b[ 6] = T1[temp[3][2]][1];
	b[ 7] = T1[temp[0][3]][1];
	b[ 8] = T1[temp[2][0]][1];
	b[ 9] = T1[temp[3][1]][1];
	b[10] = T1[temp[0][2]][1];
	b[11] = T1[temp[1][3]][1];
	b[12] = T1[temp[3][0]][1];
	b[13] = T1[temp[0][1]][1];
	b[14] = T1[temp[1][2]][1];
	b[15] = T1[temp[2][3]][1];
	*((u_int32_t*)(b   )) ^= *((u_int32_t*)rk[ROUNDS][0]);
	*((u_int32_t*)(b+ 4)) ^= *((u_int32_t*)rk[ROUNDS][1]);
	*((u_int32_t*)(b+ 8)) ^= *((u_int32_t*)rk[ROUNDS][2]);
	*((u_int32_t*)(b+12)) ^= *((u_int32_t*)rk[ROUNDS][3]);

	return 0;
}

/**
 * Decrypt a single block.
 */
int
rijndael_decrypt(rijndael_key *key, u_int8_t a[16], u_int8_t b[16])
{
	u_int8_t (*rk)[4][4] = key->keySched;
	int ROUNDS = key->ROUNDS;
	int r;
	u_int8_t temp[4][4];
	
	*((u_int32_t*)temp[0]) = *((u_int32_t*)(a   )) ^ *((u_int32_t*)rk[ROUNDS][0]);
	*((u_int32_t*)temp[1]) = *((u_int32_t*)(a+ 4)) ^ *((u_int32_t*)rk[ROUNDS][1]);
	*((u_int32_t*)temp[2]) = *((u_int32_t*)(a+ 8)) ^ *((u_int32_t*)rk[ROUNDS][2]);
	*((u_int32_t*)temp[3]) = *((u_int32_t*)(a+12)) ^ *((u_int32_t*)rk[ROUNDS][3]);

	*((u_int32_t*)(b   )) = *((u_int32_t*)T5[temp[0][0]])
			      ^ *((u_int32_t*)T6[temp[3][1]])
			      ^ *((u_int32_t*)T7[temp[2][2]]) 
			      ^ *((u_int32_t*)T8[temp[1][3]]);
	*((u_int32_t*)(b+ 4)) = *((u_int32_t*)T5[temp[1][0]])
			      ^ *((u_int32_t*)T6[temp[0][1]])
			      ^ *((u_int32_t*)T7[temp[3][2]]) 
			      ^ *((u_int32_t*)T8[temp[2][3]]);
	*((u_int32_t*)(b+ 8)) = *((u_int32_t*)T5[temp[2][0]])
			      ^ *((u_int32_t*)T6[temp[1][1]])
			      ^ *((u_int32_t*)T7[temp[0][2]]) 
			      ^ *((u_int32_t*)T8[temp[3][3]]);
	*((u_int32_t*)(b+12)) = *((u_int32_t*)T5[temp[3][0]])
			      ^ *((u_int32_t*)T6[temp[2][1]])
			      ^ *((u_int32_t*)T7[temp[1][2]]) 
			      ^ *((u_int32_t*)T8[temp[0][3]]);
	for (r = ROUNDS-1; r > 1; r--) {
		*((u_int32_t*)temp[0]) = *((u_int32_t*)(b   )) ^ *((u_int32_t*)rk[r][0]);
		*((u_int32_t*)temp[1]) = *((u_int32_t*)(b+ 4)) ^ *((u_int32_t*)rk[r][1]);
		*((u_int32_t*)temp[2]) = *((u_int32_t*)(b+ 8)) ^ *((u_int32_t*)rk[r][2]);
		*((u_int32_t*)temp[3]) = *((u_int32_t*)(b+12)) ^ *((u_int32_t*)rk[r][3]);
		*((u_int32_t*)(b   )) = *((u_int32_t*)T5[temp[0][0]])
				      ^ *((u_int32_t*)T6[temp[3][1]])
				      ^ *((u_int32_t*)T7[temp[2][2]]) 
				      ^ *((u_int32_t*)T8[temp[1][3]]);
		*((u_int32_t*)(b+ 4)) = *((u_int32_t*)T5[temp[1][0]])
				      ^ *((u_int32_t*)T6[temp[0][1]])
				      ^ *((u_int32_t*)T7[temp[3][2]]) 
				      ^ *((u_int32_t*)T8[temp[2][3]]);
		*((u_int32_t*)(b+ 8)) = *((u_int32_t*)T5[temp[2][0]])
				      ^ *((u_int32_t*)T6[temp[1][1]])
				      ^ *((u_int32_t*)T7[temp[0][2]]) 
				      ^ *((u_int32_t*)T8[temp[3][3]]);
		*((u_int32_t*)(b+12)) = *((u_int32_t*)T5[temp[3][0]])
				      ^ *((u_int32_t*)T6[temp[2][1]])
				      ^ *((u_int32_t*)T7[temp[1][2]]) 
				      ^ *((u_int32_t*)T8[temp[0][3]]);
	}
	/* last round is special */   
	*((u_int32_t*)temp[0]) = *((u_int32_t*)(b   )) ^ *((u_int32_t*)rk[1][0]);
	*((u_int32_t*)temp[1]) = *((u_int32_t*)(b+ 4)) ^ *((u_int32_t*)rk[1][1]);
	*((u_int32_t*)temp[2]) = *((u_int32_t*)(b+ 8)) ^ *((u_int32_t*)rk[1][2]);
	*((u_int32_t*)temp[3]) = *((u_int32_t*)(b+12)) ^ *((u_int32_t*)rk[1][3]);
	b[ 0] = S5[temp[0][0]];
	b[ 1] = S5[temp[3][1]];
	b[ 2] = S5[temp[2][2]];
	b[ 3] = S5[temp[1][3]];
	b[ 4] = S5[temp[1][0]];
	b[ 5] = S5[temp[0][1]];
	b[ 6] = S5[temp[3][2]];
	b[ 7] = S5[temp[2][3]];
	b[ 8] = S5[temp[2][0]];
	b[ 9] = S5[temp[1][1]];
	b[10] = S5[temp[0][2]];
	b[11] = S5[temp[3][3]];
	b[12] = S5[temp[3][0]];
	b[13] = S5[temp[2][1]];
	b[14] = S5[temp[1][2]];
	b[15] = S5[temp[0][3]];
	*((u_int32_t*)(b   )) ^= *((u_int32_t*)rk[0][0]);
	*((u_int32_t*)(b+ 4)) ^= *((u_int32_t*)rk[0][1]);
	*((u_int32_t*)(b+ 8)) ^= *((u_int32_t*)rk[0][2]);
	*((u_int32_t*)(b+12)) ^= *((u_int32_t*)rk[0][3]);

	return 0;
}

int
rijndael_makekey(rijndael_key *key, int direction, int keyLen, u_int8_t *keyMaterial)
{
	u_int8_t k[RIJNDAEL_MAXKC][4];
	int i;
	
	if (key == NULL)
		return -1;
	if ((direction != RIJNDAEL_ENCRYPT) && (direction != RIJNDAEL_DECRYPT))
		return -1;
	if ((keyLen != 128) && (keyLen != 192) && (keyLen != 256))
		return -1;

	key->ROUNDS = keyLen/32 + 6;

	/* initialize key schedule: */
	for (i = 0; i < keyLen/8; i++)
		k[i >> 2][i & 3] = (u_int8_t)keyMaterial[i]; 

	rijndael_keysched(k, key->keySched, key->ROUNDS);
	if (direction == RIJNDAEL_DECRYPT)
		rijndael_key_enc_to_dec(key->keySched, key->ROUNDS);
	return 0;
}
