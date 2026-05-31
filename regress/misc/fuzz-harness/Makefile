# NB. libssh and libopenbsd-compat should be built with the same sanitizer opts.
CC=clang-19
CXX=clang++-19
FUZZ_FLAGS=-fsanitize=address,fuzzer -fno-omit-frame-pointer
FUZZ_LIBS=-L/usr/lib/llvm-19/lib -lFuzzer

CFLAGS=-D_GNU_SOURCE=1 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-exceptions -Wno-deprecated -I ../../..
CXXFLAGS=$(CFLAGS) $(FUZZ_FLAGS)
LDFLAGS=-L ../../.. -L ../../../openbsd-compat -g
COMMON_OBJS=../../../ssh-pkcs11-client.o
LIBS=$(COMMON_OBJS) -lssh -lopenbsd-compat -lmd -lcrypto -lfido2 -lcbor $(FUZZ_LIBS)
SK_NULL_OBJS=ssh-sk-null.o
COMMON_DEPS=../../../libssh.a $(COMMON_OBJS)

TARGETS=pubkey_fuzz sig_fuzz authopt_fuzz authkeys_fuzz sshsig_fuzz \
	sshsigopt_fuzz privkey_fuzz kex_fuzz agent_fuzz \
	mkcorpus_sntrup761 sntrup761_enc_fuzz sntrup761_dec_fuzz \
	ssh_client_session_fuzz sftp_server_msg_fuzz authfd_reply_fuzz \
	sftp_client_fuzz misc_parse_fuzz ssh_channels_fuzz \
	session_channel_req_fuzz sshd_auth_session_fuzz hostfile_fuzz \
	mux_fuzz sshconfig_fuzz

all: $(TARGETS)

.cc.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

pubkey_fuzz: pubkey_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ pubkey_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sig_fuzz: sig_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sig_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

authopt_fuzz: authopt_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ authopt_fuzz.o $(SK_NULL_OBJS) ../../../auth-options.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

authkeys_fuzz: authkeys_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ authkeys_fuzz.o $(SK_NULL_OBJS) ../../../auth-options.o ../../../auth2-pubkeyfile.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sshsig_fuzz: sshsig_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshsig_fuzz.o $(SK_NULL_OBJS) ../../../sshsig.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sshsigopt_fuzz: sshsigopt_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshsigopt_fuzz.o $(SK_NULL_OBJS) ../../../sshsig.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

privkey_fuzz: privkey_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ privkey_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

kex_fuzz: kex_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ kex_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

sshconfig_fuzz: sshconfig_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshconfig_fuzz.o $(SK_NULL_OBJS) ../../../readconf.o \
		../../../addrmatch.o ../../../misc.o ../../../krl.o \
		$(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

agent_fuzz: agent_fuzz.o agent_fuzz_helper.o sk-dummy.o ../../../ssh-sk.o $(COMMON_DEPS)
	$(CXX) -o $@ agent_fuzz.o agent_fuzz_helper.o sk-dummy.o ../../../ssh-sk.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

agent_fuzz_helper.o: agent_fuzz_helper.c ../../../ssh-agent.c

ssh_client_session_fuzz: ssh_client_session_fuzz.o ssh_client_session_fuzz_helper.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ ssh_client_session_fuzz.o ssh_client_session_fuzz_helper.o $(SK_NULL_OBJS) ../../../sshconnect.o ../../../readconf.o -Wl,--wrap=ssh_packet_write_wait,--wrap=read_passphrase $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

ssh_client_session_fuzz_helper.o: ssh_client_session_fuzz_helper.c ../../../sshconnect2.c

sftp_server_msg_fuzz: sftp_server_msg_fuzz.o sftp_server_msg_fuzz_helper.o fuzz_arena.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sftp_server_msg_fuzz.o sftp_server_msg_fuzz_helper.o fuzz_arena.o $(SK_NULL_OBJS) ../../../sftp-common.o -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

sftp_server_msg_fuzz_helper.o: sftp_server_msg_fuzz_helper.c ../../../sftp-server.c

authfd_reply_fuzz: authfd_reply_fuzz.o fuzz_arena.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ authfd_reply_fuzz.o fuzz_arena.o $(SK_NULL_OBJS) -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sftp_client_fuzz: sftp_client_fuzz.o fuzz_arena.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sftp_client_fuzz.o fuzz_arena.o $(SK_NULL_OBJS) ../../../sftp-client.o ../../../sftp-common.o -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

sk-dummy.o: ../sk-dummy/sk-dummy.c
	$(CC) $(CFLAGS) -c -o $@ ../sk-dummy/sk-dummy.c -DSK_DUMMY_INTEGRATE=1 $(LDFLAGS) $(FUZZ_FLAGS)

mkcorpus_sntrup761: mkcorpus_sntrup761.o
	$(CC) -o $@ mkcorpus_sntrup761.o $(LDFLAGS) -lcrypto

sntrup761_dec_fuzz: sntrup761_dec_fuzz.o
	$(CXX) -o $@ sntrup761_dec_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(FUZZ_LIBS) -lcrypto

sntrup761_enc_fuzz: sntrup761_enc_fuzz.o
	$(CXX) -o $@ sntrup761_enc_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(FUZZ_LIBS) -lcrypto

misc_parse_fuzz: misc_parse_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ misc_parse_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

ssh_channels_fuzz: ssh_channels_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ ssh_channels_fuzz.o $(SK_NULL_OBJS) -Wl,--wrap=ssh_packet_disconnect,--wrap=sshpkt_fatal $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

session_channel_req_fuzz: session_channel_req_fuzz.o session_channel_req_fuzz_helper.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ session_channel_req_fuzz.o session_channel_req_fuzz_helper.o $(SK_NULL_OBJS) ../../../session.o ../../../sshpty.o ../../../sshlogin.o ../../../servconf.o ../../../auth.o ../../../auth-options.o ../../../groupaccess.o ../../../auth2-pubkeyfile.o -Wl,--wrap=ssh_packet_disconnect,--wrap=sshpkt_fatal,--wrap=do_exec,--wrap=do_exec_pty,--wrap=do_exec_no_pty $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

sshd_auth_session_fuzz: sshd_auth_session_fuzz.o sshd_auth_session_fuzz_helper.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshd_auth_session_fuzz.o sshd_auth_session_fuzz_helper.o $(SK_NULL_OBJS) ../../../auth.o ../../../auth2-none.o ../../../auth2-passwd.o ../../../auth2-pubkey.o ../../../auth2-kbdint.o ../../../auth2-hostbased.o ../../../auth2-chall.o ../../../auth2-methods.o ../../../auth2-pubkeyfile.o ../../../auth-options.o ../../../servconf.o ../../../groupaccess.o ../../../srclimit.o -Wl,--wrap=ssh_packet_write_wait $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

hostfile_fuzz: hostfile_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ hostfile_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

mux_fuzz: mux_fuzz.o mux_fuzz_helper.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ mux_fuzz.o mux_fuzz_helper.o $(SK_NULL_OBJS) ../../../readconf.o -Wl,--wrap=ssh_packet_disconnect,--wrap=sshpkt_fatal,--wrap=ask_permission,--wrap=channel_setup_local_fwd_listener,--wrap=channel_connect_stdio_fwd,--wrap=channel_request_remote_forwarding,--wrap=channel_request_rforward_cancel,--wrap=channel_cancel_lport_listener $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

mux_fuzz_helper.o: mux_fuzz_helper.c ../../../mux.c

clean:
	-rm -f *.o $(TARGETS)

cleandir: clean

