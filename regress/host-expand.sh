#	$OpenBSD: host-expand.sh,v 1.5 2017/04/30 23:34:55 djm Exp $
#	Placed in the Public Domain.

tid="expand %h and %n"

echo 'PermitLocalCommand yes' >> $OBJ/ssh_proxy
if [ "$os" == "windows" ]; then
	# Use bash shell for local command execution as the default shell in windows is cmd.exe
	printf 'LocalCommand ' >> $OBJ/ssh_proxy
	printf $TEST_SHELL_PATH >> $OBJ/ssh_proxy
	printf ' -c "printf \\"%%%%s\\n\\" \\"%%n\\" \\"%%h\\""\n' >> $OBJ/ssh_proxy
else
	printf 'LocalCommand printf "%%%%s\\n" "%%n" "%%h"\n' >> $OBJ/ssh_proxy
fi

cat >$OBJ/expect <<EOE
somehost
127.0.0.1
EOE

${SSH} -F $OBJ/ssh_proxy somehost true >$OBJ/actual
diff $OBJ/expect $OBJ/actual || fail "$tid"

