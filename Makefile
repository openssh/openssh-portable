# Generated automatically from Makefile.in by configure.
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
mandir=${prefix}/man

CC=gcc
OPT_FLAGS=-g
CFLAGS=$(OPT_FLAGS) -Wall -DETCDIR=\"${prefix}/etc\" -DHAVE_CONFIG_H
TARGETS=bin/libssh.a bin/ssh bin/sshd bin/ssh-add bin/ssh-keygen bin/ssh-agent bin/scp
LFLAGS=-L./bin
LIBS=-lssh -lpam -ldl -lpwdb -lz -lutil -lcrypto 
AR=ar
RANLIB=ranlib

OBJS=	authfd.o authfile.o auth-passwd.o auth-rhosts.o auth-rh-rsa.o \
		auth-rsa.o bufaux.o buffer.o canohost.o channels.o cipher.o \
		clientloop.o compress.o crc32.o deattack.o helper.o hostfile.o \
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
	rm -f *.o core bin/* config.status config.cache config.log
	
install:
	install -d $(bindir)
	install -d $(sbindir)
	install -d $(mandir)
	install -d $(mandir)/man1
	install -d $(mandir)/man8
	install -s -c bin/ssh $(bindir)/ssh
	install -s -c bin/scp $(bindir)/scp
	install -s -c bin/ssh-add $(bindir)/ssh-add
	install -s -c bin/ssh-agent $(bindir)/ssh-agent
	install -s -c bin/ssh-keygen $(bindir)/ssh-keygen
	install -s -c bin/sshd $(sbindir)/sshd
	install -m644 -c ssh.1 $(mandir)/man1/ssh.1
	install -m644 -c scp.1 $(mandir)/man1/scp.1
	install -m644 -c ssh-add.1 $(mandir)/man1/ssh-add.1
	install -m644 -c ssh-agent.1 $(mandir)/man1/ssh-agent.1
	install -m644 -c ssh-keygen.1 $(mandir)/man1/ssh-keygen.1
	install -m644 -c sshd.8 $(mandir)/man8/sshd.8

distclean: clean
	rm -f Makefile config.h *~
	rm -rf bin

mrproper: distclean
