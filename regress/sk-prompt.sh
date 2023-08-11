tid="security key prompt"

sk_keys=""
for i in ${SSH_KEYTYPES}; do
	case "$i" in
		sk-*)	sk_keys="$sk_keys $i" ;;
	esac
done

# For all security key types, make sure that SecurityKeyPromptCommand actually calls the command.
for ut in $sk_keys; do
	verbose "KEY: $ut"
	cat $ut.pub > $OBJ/authorized_keys_$USER  # ensure it uses this key

	stderr=$(${SSH} -F $OBJ/ssh_proxy -o SecurityKeyPromptCommand=./sk-prompt-notifier.sh -i $ut host true 2>&1 > /dev/null)
	if [ $? -ne 0 ]; then
		fail "ssh key $ut failed"
	fi
	if [[ $stderr != "TOUCH IT! Confirm user presence for key"* ]]; then
		fail "ssh key $ut did not use SecurityKeyPromptCommand, stderr was $stderr"
	fi
done
