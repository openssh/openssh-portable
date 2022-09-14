docker run --net=host \
    -i \
    -e REDIS_HOST=192.168.88.10 \
    -e HOST_ID=123456789ABC \
    -e LOGIN_URL=http://192.168.88.10:4200/login \
    -e PORT=9999 \
    --cap-add=NET_ADMIN \
    -v /dev/net/tun:/dev/net/tun \
    -v /tmp/ferrumgate:/etc/ferrumgate \
    secure.server
