OPT_FLAGS=-g
CFLAGS=$(OPT_FLAGS) -Wall -DETCDIR=\"/etc/ssh\" -DHAVE_PAM -DHAVE_PWDB
TARGETS=bin/libssh.a bin/ssh bin/sshd bin/ssh-add bin/ssh-keygen bin/ssh-agent bin/scp
LFLAGS=-L./bin
LIBS=-lssh -lcrypto -lz -lutil  -lpwdb -lpam -ldl
AR=ar
RANLIB=ranlib

OBJS=	authfd.o authfile.o auth-passwd.o auth-rhosts.o auth-rh-rsa.o \
		auth-rsa.o bufaux.o buffer.o canohost.o channels.o cipher.o \
		clientloop.o compress.o crc32.o deattack.o hostfile.o \
		log-client.o login.o log-server.o match.o mpaux.o packet.o pty.o \
		readconf.o readpass.o rsa.o servconf.o serverloop.o \
		sshconnect.o tildexpand.o ttymodes.o uidswap.o xmalloc.o \
		helper.o mktemp.o strlcpy.o rc4.o

all: $(OBJS) $(TARGETS)

bin/libssh.a: authfd.o authfile.o bufaux.o buffer.o canohost.o channels.o cipher.o compat.o compress.o crc32.o deattack.o hostfile.o match.o mpaux.o nchan.o packet.o readpass.o rsa.o tildexpand.o ttymodes.o uidswap.o xmalloc.o helper.o rc4.o mktemp.o strlcpy.o
	[ -d bin ] || mkdir bin
	$(AR) rv $@ $^
	$(RANLIB) $@

bin/ssh: ssh.o sshconnect.o log-client.o readconf.o clientloop.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

bin/sshd:	sshd.o auth-rhosts.o auth-passwd.o auth-rsa.o auth-rh-rsa.o pty.o log-server.o login.o servconf.o serverloop.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

bin/scp:	scp.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

bin/ssh-add: ssh-add.o log-client.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

bin/ssh-agent: ssh-agent.o log-client.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

bin/ssh-keygen: ssh-keygen.o log-client.o
	[ -d bin ] || mkdir bin
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

clean:
	rm -f *.o core bin/*
	
