#!/bin/sh
#       $OpenBSD: sntrup761.sh,v 1.3 2021/01/03 18:05:21 tobhe Exp $
#       Placed in the Public Domain.
#
AUTHOR="supercop-20201130/crypto_kem/sntrup761/ref/implementors"
FILES="
	supercop-20201130/crypto_kem/sntrup761/ref/uint64.h
	supercop-20201130/crypto_kem/sntrup761/ref/uint16.h
	supercop-20201130/crypto_kem/sntrup761/ref/uint32.h
	supercop-20201130/crypto_kem/sntrup761/ref/int8.h
	supercop-20201130/crypto_kem/sntrup761/ref/int16.h
	supercop-20201130/crypto_kem/sntrup761/ref/int32.h
	supercop-20201130/crypto_kem/sntrup761/ref/uint32.c
	supercop-20201130/crypto_kem/sntrup761/ref/int32.c
	supercop-20201130/crypto_kem/sntrup761/ref/paramsmenu.h
	supercop-20201130/crypto_kem/sntrup761/ref/params.h
	supercop-20201130/crypto_kem/sntrup761/ref/Decode.h
	supercop-20201130/crypto_kem/sntrup761/ref/Decode.c
	supercop-20201130/crypto_kem/sntrup761/ref/Encode.h
	supercop-20201130/crypto_kem/sntrup761/ref/Encode.c
	supercop-20201130/crypto_kem/sntrup761/ref/kem.c
"
SORT_I32="
	supercop-20201130/crypto_sort/int32/portable4/sort.c
"
SORT_U32="supercop-20201130/crypto_sort/uint32/useint32/sort.c"
###

set -e
cd $1
echo -n '/*  $'
echo 'OpenBSD: $ */'
echo
echo '/*'
echo ' * Public Domain, Authors:'
sed -e '/Alphabetical order:/d' -e 's/^/ * - /' < $AUTHOR
echo ' */'
echo
echo '#include <string.h>'
echo '#include "crypto_api.h"'
echo '#include "int32_minmax.inc"'
echo
echo '#define CRYPTO_NAMESPACE(s) s'
echo
for i in $SORT_I32; do
	echo "/* from $i */"
	grep \
	   -v '#include' $i | \
	   sed -e "s/void crypto_sort/static void crypto_sort_int32/g"
	echo
done
echo "/* from $SORT_U32 */"
grep \
   -v '#include' $SORT_U32 | \
   sed -e "s/void crypto_sort/static void crypto_sort_uint32/g"
echo
for i in $FILES; do
	echo "/* from $i */"
	grep \
	   -v '#include' $i | \
	   sed -e "s/crypto_kem_/crypto_kem_sntrup761_/g" \
		-e "s/^extern void /static void /" \
		-e "s/^void /static void /" \
		-e "/^typedef int32_t int32;$/d"
	echo
done
