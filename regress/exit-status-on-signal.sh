# This test performs validation that ssh client is not successive on being terminated
# Test assumes 2 seconds interval is enough to make sure we are killing it affer initial communication is over

tid="exit status on signal"

verbose "test $tid: testing signal handling"

# spawn client in background to kill it in 2 seconds
${SSH} -F $OBJ/ssh_proxy otherhost sleep 10 &
ssh_pid=$!

sleep 2

kill $ssh_pid
wait $ssh_pid
exit_code=$?

if [ $exit_code -eq 0 ];
then
   fail "ssh client should fail on signal"
fi

