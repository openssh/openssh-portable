#	Placed in the Public Domain.

tid="testing webauthn-sk-ecdsa-sha2-nistp256@openssh.com compatibility"
export tid

ssh -Q key | fgrep -q sk-ecdsa-sha2-nistp256@openssh.com ||	skip "sk-ecdsa-sha2-nistp256@openssh.com key support not available"
ssh -Q key | fgrep -q sk-ecdsa-sha2-nistp256-cert-v01@openssh.com || skip "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com key support not available"


SSHAGENT="$OBJ/misc/webauthn-dummy-agent/webauthn-dummy-agent"
export SSHAGENT


trace "create sk_dummy key for testing"

rm -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com" "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub" "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-cert.pub"
${SSHKEYGEN} -q -N '' -t ecdsa-sk -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com" \
	|| fail "ssh-keygen failed"

rm -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca" "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca.pub"
${SSHKEYGEN} -q -N '' -t ecdsa-sk -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca" \
	|| fail "ssh-keygen failed"


trace "start webauthn-dummy-agent, args ${EXTRA_AGENT_ARGS}"

start_ssh_agent "$EXTRA_AGENT_ARGS"


trace "load simple ecdsa_sk key into agent"

${SSHADD} -k "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com"


trace "check if key is usable"

${SSHADD} -T "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub" \
	|| fail "key from agent not usable"


trace "sshsig with webauthn-sk-ecdsa-sha2-nistp256@openssh.com signature"

printf "This is a test, this is only a test" > "$OBJ/signed-data"
rm -f "$OBJ/signed-data.sig"
${SSHKEYGEN} -Y sign -n regress -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub" "$OBJ/signed-data"
${SSHKEYGEN} -Y check-novalidate -n regress -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub" -s "$OBJ/signed-data.sig" < "$OBJ/signed-data" \
	|| fail "sshsig with webauthn-sk-ecdsa-sha2-nistp256@openssh.com signature did not verify"


trace "signing a certificate"

${SSHADD} -k "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca"
${SSHKEYGEN} -U -s "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca.pub" -I "user1" -n "principal1" -V "+365d" "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub"
${SSHKEYGEN} -L -f "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-cert.pub" | grep "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" \
	|| fail "certificate not using the expected CASignatureAlgorithm webauthn-sk-ecdsa-sha2-nistp256@openssh.com"


trace "connect with key challenge signed via agent with webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

printf '' > "$OBJ/authorized_keys_$USER"
cat "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com.pub" >> "$OBJ/authorized_keys_$USER"

# Remove explicit identity directives from ssh_proxy
mv "$OBJ/ssh_proxy" "$OBJ/ssh_proxy_bak"
grep -vi IdentityFile "$OBJ/ssh_proxy_bak" > "$OBJ/ssh_proxy"

${SSH} -F "$OBJ/ssh_proxy" somehost exit 52
r=$?
if [ $r -ne 52 ]; then
	fail "ssh connect with failed (exit code $r)"
fi


trace "connect with cert signed with webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
printf '' > "$OBJ/authorized_keys_$USER"
printf "cert-authority,principals=\"principal1\" " >> "$OBJ/authorized_keys_$USER"
cat "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com-user-ca.pub" >> "$OBJ/authorized_keys_$USER"

${SSHADD} -D
${SSHADD} "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com"
${SSHADD} -d -k "$OBJ/sk-ecdsa-sha2-nistp256@openssh.com"

echo CASignatureAlgorithms=webauthn-sk-ecdsa-sha2-nistp256@openssh.com >> "$OBJ/sshd_proxy"

${SSH} -F "$OBJ/ssh_proxy" somehost exit 52
r=$?
if [ $r -ne 52 ]; then
	fail "ssh connect failed (exit code $r) with cert signed with webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
fi
