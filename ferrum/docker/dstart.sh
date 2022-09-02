#!/bin/bash
ulimit -c unlimited
#echo "/cores/core-%e-%t-%s" > /proc/sys/kernel/core_pattern

echo "starting server"
cat /proc/sys/kernel/core_pattern

echo "***************ip address**************"

/bin/ip address
echo "***************************************"

OPT_PORT=3333
if [ ! -z "$PORT" ]
then
    OPT_PORT=$PORT
fi
echo "listen on port $OPT_PORT"


OPT_REDIS_HOST=localhost
if [ ! -z "$REDIS_HOST" ]
then
    OPT_REDIS_HOST=$REDIS_HOST
fi
echo "redis host $OPT_REDIS_HOST"

OPT_LOGIN_URL=http://localhost:4200/login
if [ ! -z "$LOGIN_URL" ]
then
    OPT_LOGIN_URL=$LOGIN_URL
fi
echo "login url $OPT_LOGIN_URL"



sed -i "s/Port 3333/Port ${OPT_PORT}/g" /ferrum/etc/sshd_config
/ferrum/bin/ssh-keygen -q -t rsa -b 4096 -f /ferrum/etc/ssh_host_rsa_key -N '' <<<y >/dev/null 2>&1
/ferrum/bin/ssh-keygen -q -t ecdsa -b 521 -f /ferrum/etc/ssh_host_ecdsa_key -N  ''<<<y >/dev/null 2>&1
/ferrum/bin/ssh-keygen -q -t ed25519 -f /ferrum/etc/ssh_host_ed25519_key -N '' <<<y >/dev/null 2>&1
echo "starting server"
REDIS_HOST=$OPT_REDIS_HOST LOGIN_URL=$OPT_LOGIN_URL  \
/ferrum/sbin/secure.server -D -e -f /ferrum/etc/sshd_config


echo "finished server"
