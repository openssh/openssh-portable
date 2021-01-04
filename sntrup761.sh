#!/bin/sh
#       $OpenBSD: sntrup761.sh,v 1.4 2021/01/04 21:58:58 dtucker Exp $
#       Placed in the Public Domain.
#
AUTHOR="supercop-20201130/crypto_kem/sntrup761/ref/implementors"
FILES="
	supercop-20201130/crypto_sort/int32/portable4/int32_minmax.inc
	supercop-20201130/crypto_sort/int32/portable4/sort.c
	supercop-20201130/crypto_sort/uint32/useint32/sort.c
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
echo
echo '#define CRYPTO_NAMESPACE(s) s'
echo
for i in $FILES; do
	echo "/* from $i */"
	grep \
	   -v '#include' $i | \
	case "$i" in
	# Use int64_t for intermediate values in int32_MINMAX to prevent signed
	# 32-bit integer overflow when called by crypto_sort_uint32.
	*/int32_minmax.inc)
	    sed -e "s/int32 ab = b ^ a/int64_t ab = (int64_t)b ^ (int64_t)a/" \
	    -e "s/int32 c = b - a/int64_t c = (int64_t)b - (int64_t)a/"
	    ;;
	*/int32/portable4/sort.c)
	    sed -e "s/void crypto_sort/static void crypto_sort_int32/g"
	    ;;
	*/uint32/useint32/sort.c)
	    sed -e "s/void crypto_sort/static void crypto_sort_uint32/g"
	    ;;
	*)
	    sed -e "s/crypto_kem_/crypto_kem_sntrup761_/g" \
		-e "s/^extern void /static void /" \
		-e "s/^void /static void /" \
		-e "/^typedef int32_t int32;$/d"
	esac
	echo
done
