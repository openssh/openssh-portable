#!/bin/sh
FILES="
	supercop-20181216/crypto_sort/int32/portable3/int32_minmax.inc
	supercop-20181216/crypto_sort/int32/portable3/sort.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/small.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/mod3.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/modq.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/params.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/r3.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/swap.h
	supercop-20181216/crypto_kem/sntrup4591761/ref/dec.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/enc.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/keypair.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/r3_mult.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/r3_recip.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/randomsmall.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/randomweightw.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq_mult.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq_recip3.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq_round3.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/rq_rounded.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/small.c
	supercop-20181216/crypto_kem/sntrup4591761/ref/swap.c
"
###

set -e
DIR=/data/git/mfriedl
cd $DIR
echo '#include <string.h>'
echo '#include "crypto_api.h"'
echo
for i in $FILES; do
	echo "/* from $i */"
	b=$(basename $i .c)
	grep \
	   -v '#include' $i | \
	   grep -v "extern crypto_int32 small_random32" |
	   sed -e "s/crypto_kem_/crypto_kem_sntrup4591761_/g" \
		-e "s/smaller_mask/smaller_mask_${b}/g" \
		-e "s/void crypto_sort/void crypto_sort_int32/" \
		-e "s/^extern void /static void /" \
		-e "s/^void /static void /"
	echo
done
