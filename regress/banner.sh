#	$OpenBSD: banner.sh,v 1.1 2003/10/07 01:52:13 dtucker Exp $
#	Placed in the Public Domain.

tid="banner"
echo "Banner $OBJ/banner.in" >> $OBJ/sshd_proxy

for s in 0 10 100 1000 10000 100000 ; do
	if [ "$s" = "0" ]; then
		# create empty banner
		rm -f $OBJ/banner.in
		touch $OBJ/banner.in
	elif [ "$s" = "10" ]; then
		# create 10-byte banner file
		echo "abcdefghi" >$OBJ/banner.in
	else
		# increase size 10x
		cp $OBJ/banner.in $OBJ/banner.out
		for i in 0 1 2 3 4 5 6 7 8 ; do
			cat $OBJ/banner.out >> $OBJ/banner.in
		done
	fi

	trace "test banner size $s"
	verbose "test $tid: size $s"
	${SSH} -2 -F $OBJ/ssh_proxy otherhost true 2>$OBJ/banner.out
	if ! cmp $OBJ/banner.in $OBJ/banner.out ; then
		fail "banner size $s mismatch"
	fi
done

rm -f $OBJ/banner.out $OBJ/banner.in
