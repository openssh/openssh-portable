#	$OpenBSD$
#	Placed in the Public Domain.

tid="agent confirmation"

cat << _EOF > $OBJ/askpass.sh
#!/bin/sh
echo "\$1" >> $OBJ/askpass.log
test -f $OBJ/askpass-deny && exit 1
exit 0
_EOF
chmod a+x $OBJ/askpass.sh

grep -vi identityfile $OBJ/ssh_proxy > $OBJ/ssh_proxy_agent

rm -f $OBJ/user_key $OBJ/user_key.pub
${SSHKEYGEN} -q -N '' -t ed25519 -C user_key -f $OBJ/user_key || \
	fatal "ssh-keygen failed"
cp $OBJ/user_key.pub $OBJ/authorized_keys_$USER

start_agent() {
	trace "start agent $@"
	eval `env SSH_ASKPASS=$OBJ/askpass.sh SSH_ASKPASS_REQUIRE=force \
	    ${SSHAGENT} ${EXTRA_AGENT_ARGS} -s "$@"` > /dev/null || \
		fatal "could not start ssh-agent"
}

stop_agent() {
	${SSHAGENT} -k > /dev/null || fatal "could not stop ssh-agent"
}

add_key() {
	${SSHADD} -q "$@" $OBJ/user_key || fatal "ssh-add $@ failed"
}

reset_prompts() {
	rm -f $OBJ/askpass-deny
	> $OBJ/askpass.log
}

expect_prompts() {
	_n=`grep -c '^Allow use of key' $OBJ/askpass.log`
	test $_n -eq $1 || fail "$2: expected $1 prompts, got $_n"
}

expect_prompt_text() {
	grep "$1" $OBJ/askpass.log > /dev/null || \
		fail "$2: prompt does not contain \"$1\""
}

# Connect to somehost
direct() {
	${SSH} -F $OBJ/ssh_proxy_agent somehost true
}

# Connect to somehost with agent forwarding, and from there to somehost again
# using the forwarded agent.
forwarded() {
	${SSH} -A -F $OBJ/ssh_proxy_agent somehost \
	    ${SSH} -F $OBJ/ssh_proxy_agent somehost true
}

verbose "no confirmation by default"
start_agent
add_key
reset_prompts
direct || fail "direct connection failed"
forwarded || fail "forwarded connection failed"
expect_prompts 0 "default"
stop_agent

verbose "confirm-forwarded: local use"
start_agent -O confirm-forwarded
add_key
reset_prompts
direct || fail "direct connection failed"
expect_prompts 0 "confirm-forwarded local"

verbose "confirm-forwarded: forwarded use"
reset_prompts
forwarded || fail "forwarded connection failed"
expect_prompts 1 "confirm-forwarded forwarded"
expect_prompt_text 'requested from host "somehost" via agent forwarding' \
	"confirm-forwarded forwarded"
expect_prompt_text "for login as \"$USER\" to host key " \
	"confirm-forwarded forwarded"
# The destination host key shown must be one of the server's host keys.
_fp=`sed -n 's/^for login as .* to host key [^ ]* \(.*\)$/\1/p' \
	$OBJ/askpass.log`
test -z "$_fp" && fail "no destination host key in prompt"
${SSHKEYGEN} -lf $OBJ/known_hosts | grep " $_fp " > /dev/null || \
	fail "destination host key $_fp not in known_hosts"

verbose "confirm-forwarded: forwarded signature that is not a login"
reset_prompts
echo data > $OBJ/signdata
${SSH} -A -F $OBJ/ssh_proxy_agent somehost \
    ${SSHKEYGEN} -q -Y sign -n file -f $OBJ/user_key.pub $OBJ/signdata \
    2>/dev/null || fail "forwarded ssh-keygen -Y sign failed"
expect_prompts 1 "confirm-forwarded sign"
expect_prompt_text "NOT A LOGIN REQUEST" "confirm-forwarded sign"

verbose "confirm-forwarded: forwarded use refused"
reset_prompts
touch $OBJ/askpass-deny
forwarded 2>/dev/null && fail "forwarded connection succeeded"
expect_prompts 1 "confirm-forwarded refused"
stop_agent

verbose "confirm-forwarded: key also added with -c"
start_agent -O confirm-forwarded
add_key -c
reset_prompts
direct || fail "direct connection failed"
expect_prompts 1 "confirm-forwarded -c local"
reset_prompts
forwarded || fail "forwarded connection failed"
expect_prompts 2 "confirm-forwarded -c forwarded"
stop_agent

verbose "destination-constrained key names hosts"
start_agent
add_key -c -H $OBJ/known_hosts -h localhost-with-alias \
	-h "localhost-with-alias>localhost-with-alias"
reset_prompts
forwarded || fail "forwarded connection failed"
expect_prompts 2 "constrained"
_h='"localhost-with-alias"'
expect_prompt_text "to host $_h" "constrained"
expect_prompt_text "to host $_h via host $_h" "constrained forwarded"
stop_agent

rm -f $OBJ/askpass.sh $OBJ/askpass.log \
	$OBJ/askpass-deny $OBJ/ssh_proxy_agent $OBJ/user_key $OBJ/user_key.pub \
	$OBJ/signdata $OBJ/signdata.sig
