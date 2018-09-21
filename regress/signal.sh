#!/bin/sh
tid="escape char ~ST"

start_sshd

{ sleep 5; printf ~ST;} | ${SSH} -F $OBJ/ssh_config -tt somehost "alarm(){ echo \"ALARM\"; exit 124; };

expected(){ echo \"TERM\"; exit 0; };

trap alarm ALRM;
trap expected TERM;
(sleep 10 && kill -ALRM \$\$) &
wait \$!;
"

ret=$?

if [ $ret -ne 0 ]
then
  fail "Fail escape char with exitcode : $ret"
fi
