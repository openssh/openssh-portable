docker stop redisdocker
docker run --name redisdocker --rm -d -ti --net=host redis:7.0-rc2