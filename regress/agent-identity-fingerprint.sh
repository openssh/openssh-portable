# Agent fingerprint selection must offer only the requested agent key.
# Placed in the Public Domain.

tid="agent identity fingerprint"

rm -f $OBJ/agent-fp-* $OBJ/agent-fp.sock
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -a $OBJ/agent-fp.sock -s` \
    >`ssh_logfile ssh-agent`
[ $? -eq 0 ] || fatal "could not start ssh-agent"

for n in first selected absent; do
	${SSHKEYGEN} -q -N '' -t ed25519 -f $OBJ/agent-fp-$n \
	    || fatal "could not generate $n key"
done
${SSHADD} $OBJ/agent-fp-first $OBJ/agent-fp-selected > /dev/null 2>&1 \
    || fatal "could not add agent keys"

first=`${SSHKEYGEN} -lf $OBJ/agent-fp-first.pub | awk '{print $2}'`
selected=`${SSHKEYGEN} -lf $OBJ/agent-fp-selected.pub | awk '{print $2}'`
absent=`${SSHKEYGEN} -lf $OBJ/agent-fp-absent.pub | awk '{print $2}'`
echo "${selected}" | grep '^SHA256:' > /dev/null || fatal "bad fingerprint"

cp $OBJ/agent-fp-selected.pub $OBJ/authorized_keys_$USER
echo 'MaxAuthTries 1' >> $OBJ/sshd_proxy

trace "select second agent key with -u"
${SSH} -F $OBJ/ssh_proxy -u "$selected" somehost exit 52 \
    > $OBJ/agent-fp.log 2>&1
[ $? -eq 52 ] || fail "selected agent key did not authenticate"

trace "select agent key from ssh_config"
cp $OBJ/ssh_proxy $OBJ/ssh_proxy_fp
echo "AgentIdentityFingerprint $selected" >> $OBJ/ssh_proxy_fp
${SSH} -F $OBJ/ssh_proxy_fp somehost exit 52 > $OBJ/agent-fp.log 2>&1
[ $? -eq 52 ] || fail "configured agent key did not authenticate"

trace "-u overrides ssh_config"
sed 's/^MaxAuthTries 1$/MaxAuthTries 2/' $OBJ/sshd_proxy \
    > $OBJ/sshd_proxy_fp
mv $OBJ/sshd_proxy_fp $OBJ/sshd_proxy
SSH_ASKPASS=/bin/false SSH_ASKPASS_REQUIRE=force DISPLAY=:1 \
    ${SSH} -vv -F $OBJ/ssh_proxy_fp -u "$first" \
    -o PasswordAuthentication=yes -o BatchMode=no \
    -o NumberOfPasswordPrompts=1 somehost true \
    > $OBJ/agent-fp.log 2>&1
[ $? -ne 0 ] || fail "rejected override key unexpectedly authenticated"
grep 'Selected agent identity .* was rejected' $OBJ/agent-fp.log \
    > /dev/null || fail "rejected key error missing"
grep 'Next authentication method: password' $OBJ/agent-fp.log \
    > /dev/null || fail "password fallback after rejection missing"

trace "absent agent key"
${SSH} -F $OBJ/ssh_proxy -u "$absent" somehost true \
    > $OBJ/agent-fp.log 2>&1
[ $? -ne 0 ] || fail "absent key unexpectedly authenticated"
grep 'Selected agent identity .* is not present' $OBJ/agent-fp.log \
    > /dev/null || fail "absent key error missing"

trace "missing agent falls back to password"
SSH_AUTH_SOCK=/nonexistent SSH_ASKPASS=/bin/false \
    SSH_ASKPASS_REQUIRE=force DISPLAY=:1 \
    ${SSH} -vv -F $OBJ/ssh_proxy -u "$selected" \
    -o PasswordAuthentication=yes -o BatchMode=no \
    -o NumberOfPasswordPrompts=1 somehost true \
    > $OBJ/agent-fp.log 2>&1
[ $? -ne 0 ] || fail "missing agent unexpectedly authenticated"
grep 'Selected agent identity .* is unavailable' $OBJ/agent-fp.log \
    > /dev/null || fail "missing agent error missing"
grep 'Next authentication method: password' $OBJ/agent-fp.log \
    > /dev/null || fail "password fallback after missing agent missing"

trace "partial fingerprint is invalid"
partial=`echo "$selected" | cut -c1-30`
${SSH} -G -F $OBJ/ssh_proxy -u "$partial" somehost \
    > $OBJ/agent-fp.log 2>&1
[ $? -ne 0 ] || fail "partial fingerprint was accepted"

${SSHAGENT} -k > /dev/null 2>&1
