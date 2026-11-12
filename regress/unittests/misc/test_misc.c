/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "channels.h"
#include "canohost.h"
#include "monitor_fdpass.h"
#include "packet.h"

#include "log.h"
#include "misc.h"
#include "xmalloc.h"

#ifndef ASSERT_SSIZE_T_EQ
#define ASSERT_SSIZE_T_EQ(a1, a2) ASSERT_LONG_LONG_EQ((long long)(a1), (long long)(a2))
#endif

void test_misc(void);

static void
test_chop(void)
{
	char *s;

	TEST_START("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	free(s);
	TEST_DONE();

	TEST_START("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	free(s);
	TEST_DONE();

	TEST_START("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	free(s);
	TEST_DONE();

	TEST_START("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	free(s);
	TEST_DONE();

	TEST_START("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	free(s);
	TEST_DONE();

	TEST_START("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	free(s);
	TEST_DONE();

	TEST_START("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	free(s);
	TEST_DONE();

	TEST_START("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	free(s);
	TEST_DONE();

	TEST_START("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	free(s);
	TEST_DONE();
}

static void
test_rtrim(void)
{
	char *s;

	TEST_START("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	free(s);
	TEST_DONE();

	TEST_START("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	free(s);
	TEST_DONE();

	TEST_START("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	free(s);
	TEST_DONE();

	TEST_START("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	free(s);
	TEST_DONE();

	TEST_START("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	free(s);
	TEST_DONE();

	TEST_START("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	free(s);
	TEST_DONE();

	TEST_START("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	free(s);
	TEST_DONE();
}

static void
test_strprefix(void)
{
	const char *s;

	TEST_START("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, NULL);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, NULL);
	TEST_DONE();

	TEST_START("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, NULL);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();

	TEST_START("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, NULL);
	TEST_DONE();

	TEST_START("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, NULL);
	ASSERT_STRING_EQ(s, "hello");
	TEST_DONE();

	TEST_START("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, NULL);
	TEST_DONE();

	TEST_START("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, NULL);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, NULL);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();
}

static void
test_fmt_timeframe(void)
{
	TEST_START("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_DONE();

	TEST_START("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_DONE();

	TEST_START("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_DONE();
}

static void
test_arglist(void)
{
	arglist args;
	u_int i;

	memset(&args, 0, sizeof(args));

	TEST_START("addargs initial");
	addargs(&args, "one");
	ASSERT_U_INT_EQ(args.num, 1);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, NULL);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_PTR_EQ(args.list[1], NULL);
	TEST_DONE();

	TEST_START("addargs second");
	addargs(&args, "two");
	ASSERT_U_INT_EQ(args.num, 2);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, NULL);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_PTR_EQ(args.list[2], NULL);
	TEST_DONE();

	TEST_START("addargs with format");
	addargs(&args, "three=%d", 3);
	ASSERT_U_INT_EQ(args.num, 3);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, NULL);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], NULL);
	TEST_DONE();

	TEST_START("replacearg middle");
	replacearg(&args, 1, "TWO!");
	ASSERT_U_INT_EQ(args.num, 3);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], NULL);
	TEST_DONE();

	TEST_START("replacearg first");
	replacearg(&args, 0, "ONE!");
	ASSERT_U_INT_EQ(args.num, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], NULL);
	TEST_DONE();

	TEST_START("replacearg last");
	replacearg(&args, 2, "THREE=3!");
	ASSERT_U_INT_EQ(args.num, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], NULL);
	TEST_DONE();

	TEST_START("replacearg with format");
	replacearg(&args, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(args.num, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "two=2");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], NULL);
	TEST_DONE();

	TEST_START("addargs reallocation");
	for (i = args.num; i < 33; i++)
		addargs(&args, "pad-%d", i);
	ASSERT_U_INT_EQ(args.num, 33);
	ASSERT_U_INT_GE(args.nalloc, 33);
	ASSERT_STRING_EQ(args.list[32], "pad-32");
	ASSERT_PTR_EQ(args.list[33], NULL);
	TEST_DONE();

	TEST_START("freeargs");
	freeargs(&args);
	ASSERT_U_INT_EQ(args.num, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, NULL);
	TEST_DONE();

	TEST_START("freeargs on NULL");
	freeargs(NULL);
	TEST_DONE();

	TEST_START("freeargs on empty");
	memset(&args, 0, sizeof(args));
	freeargs(&args);
	ASSERT_U_INT_EQ(args.num, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, NULL);
	TEST_DONE();
}

static void
test_tohex(void)
{
	char *hex;

	TEST_START("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	free(hex);
	TEST_DONE();

	TEST_START("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	free(hex);
	TEST_DONE();

	TEST_START("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	free(hex);
	TEST_DONE();
}

static void
test_lowercase(void)
{
	char *s;

	TEST_START("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	free(s);
	TEST_DONE();

	TEST_START("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	free(s);
	TEST_DONE();
}

static void
test_path_absolute(void)
{
	TEST_START("path_absolute absolute");
	ASSERT_INT_EQ(path_absolute("/foo/bar"), 1);
	TEST_DONE();

	TEST_START("path_absolute relative");
	ASSERT_INT_EQ(path_absolute("foo/bar"), 0);
	TEST_DONE();

	TEST_START("path_absolute empty");
	ASSERT_INT_EQ(path_absolute(""), 0);
	TEST_DONE();
}

static void
test_stringlist(void)
{
	char **list = NULL;

	TEST_START("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, NULL);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], NULL);
	TEST_DONE();

	TEST_START("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, NULL);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], NULL);
	TEST_DONE();

	TEST_START("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, NULL);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], NULL);
	TEST_DONE();

	TEST_START("stringlist_free");
	stringlist_free(list);
	TEST_DONE();

	TEST_START("stringlist_free NULL");
	stringlist_free(NULL);
	TEST_DONE();
}

static void
test_skip_space(void)
{
	char *s, *p;

	TEST_START("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	free(s);
	TEST_DONE();

	TEST_START("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	free(s);
	TEST_DONE();

	TEST_START("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	free(s);
	TEST_DONE();

	TEST_START("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	free(s);
	TEST_DONE();

	TEST_START("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	free(s);
	TEST_DONE();

	TEST_START("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	free(s);
	TEST_DONE();
}

static void
test_stdio_fwd_socket(void)
{
	struct ssh *ssh;
	Channel *c;
	int sp[2], in, out;
	char ch;
	struct pollfd pfd;
#ifndef DISABLE_FD_PASSING
	int mux_sp[2];
#endif
	int s1, s2;
	int p1[2], p2[2];
	int lfd;
	struct sockaddr_in sin;
	socklen_t sinlen;

	log_init("test_misc", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);

	ssh = ssh_packet_set_connection(NULL, -1, -1);
	ASSERT_PTR_NE(ssh, NULL);
	channel_init_channels(ssh);

	TEST_START("stdio_fwd dup socketpair");
	ASSERT_INT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
	ASSERT_INT_EQ(unset_nonblock(sp[0]), 0);
	ASSERT_INT_EQ(set_nonblock(sp[1]), 0);
	in = dup(sp[0]);
	out = dup(sp[0]);
	ASSERT_INT_NE(in, -1);
	ASSERT_INT_NE(out, -1);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, in, out,
	    CHANNEL_NONBLOCK_STDIO);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, in);
	ASSERT_INT_EQ(c->rfd, in);
	ASSERT_INT_EQ(c->wfd, in);
	ASSERT_INT_EQ(fcntl(out, F_GETFL), -1);
	ASSERT_INT_EQ(errno, EBADF);
	ASSERT_INT_EQ(c->force_drain, 0);
	ASSERT_INT_EQ(c->restore_block, CHANNEL_RESTORE_RFD);
#ifndef HAVE_CYGWIN
	ASSERT_INT_NE(fcntl(sp[0], F_GETFL) & O_NONBLOCK, 0);
#endif

	/* Half-close */
	chan_rcvd_ieof(ssh, c);
	ASSERT_INT_EQ(c->ostate, CHAN_OUTPUT_CLOSED);
	ASSERT_INT_EQ(c->istate, CHAN_INPUT_OPEN);
	pfd.fd = sp[1];
	pfd.events = POLLIN;
	ASSERT_INT_GE(poll(&pfd, 1, 1000), 1);
	ASSERT_SSIZE_T_EQ(read(sp[1], &ch, 1), 0);

	channel_free(ssh, c);
#ifndef HAVE_CYGWIN
	ASSERT_INT_EQ(fcntl(sp[0], F_GETFL) & O_NONBLOCK, 0);
#endif
	close(sp[0]);
	close(sp[1]);
	TEST_DONE();

#ifndef DISABLE_FD_PASSING
	TEST_START("stdio_fwd SCM_RIGHTS socketpair");
	ASSERT_INT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
	ASSERT_INT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, mux_sp), 0);
	ASSERT_INT_EQ(mm_send_fd(mux_sp[0], sp[0]), 0);
	ASSERT_INT_EQ(mm_send_fd(mux_sp[0], sp[0]), 0);
	in = mm_receive_fd(mux_sp[1]);
	out = mm_receive_fd(mux_sp[1]);
	ASSERT_INT_GE(in, 0);
	ASSERT_INT_GE(out, 0);
	ASSERT_INT_NE(in, out);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, in, out,
	    CHANNEL_NONBLOCK_SET);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, in);
	ASSERT_INT_EQ(c->rfd, in);
	ASSERT_INT_EQ(c->wfd, in);
	ASSERT_INT_EQ(fcntl(out, F_GETFL), -1);
	ASSERT_INT_EQ(errno, EBADF);
	ASSERT_INT_EQ(c->force_drain, 0);

	/* Half-close with sp[0] still open in client */
	ASSERT_INT_EQ(set_nonblock(sp[1]), 0);
	chan_rcvd_ieof(ssh, c);
	pfd.fd = sp[1];
	pfd.events = POLLIN;
	ASSERT_INT_GE(poll(&pfd, 1, 1000), 1);
	ASSERT_SSIZE_T_EQ(read(sp[1], &ch, 1), 0);

	channel_free(ssh, c);
	close(sp[0]);
	close(sp[1]);
	close(mux_sp[0]);
	close(mux_sp[1]);
	TEST_DONE();
#endif

	TEST_START("stdio_fwd distinct sockets not collapsed");
	ASSERT_INT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, sp[0], sp[1],
	    CHANNEL_NONBLOCK_SET);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, -1);
	ASSERT_INT_EQ(c->rfd, sp[0]);
	ASSERT_INT_EQ(c->wfd, sp[1]);
	ASSERT_INT_EQ(c->force_drain, 1);
	channel_free(ssh, c);

	s1 = socket(AF_UNIX, SOCK_STREAM, 0);
	s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_INT_NE(s1, -1);
	ASSERT_INT_NE(s2, -1);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, s1, s2,
	    CHANNEL_NONBLOCK_SET);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, -1);
	ASSERT_INT_EQ(c->rfd, s1);
	ASSERT_INT_EQ(c->wfd, s2);
	ASSERT_INT_EQ(c->force_drain, 1);
	channel_free(ssh, c);
	TEST_DONE();

	TEST_START("stdio_fwd pipes preserve force_drain and restore_block");
	ASSERT_INT_EQ(pipe(p1), 0);
	ASSERT_INT_EQ(pipe(p2), 0);
	ASSERT_INT_EQ(unset_nonblock(p1[0]), 0);
	ASSERT_INT_EQ(unset_nonblock(p2[1]), 0);
	in = dup(p1[0]);
	out = dup(p2[1]);
	ASSERT_INT_NE(in, -1);
	ASSERT_INT_NE(out, -1);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, in, out,
	    CHANNEL_NONBLOCK_STDIO);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, -1);
	ASSERT_INT_EQ(c->rfd, in);
	ASSERT_INT_EQ(c->wfd, out);
	ASSERT_INT_EQ(c->force_drain, 1);
	ASSERT_INT_EQ(c->restore_block,
	    CHANNEL_RESTORE_RFD | CHANNEL_RESTORE_WFD);
#ifndef HAVE_CYGWIN
	ASSERT_INT_NE(fcntl(p1[0], F_GETFL) & O_NONBLOCK, 0);
	ASSERT_INT_NE(fcntl(p2[1], F_GETFL) & O_NONBLOCK, 0);
#endif

	channel_free(ssh, c);
#ifndef HAVE_CYGWIN
	ASSERT_INT_EQ(fcntl(p1[0], F_GETFL) & O_NONBLOCK, 0);
	ASSERT_INT_EQ(fcntl(p2[1], F_GETFL) & O_NONBLOCK, 0);
#endif
	close(p1[0]);
	close(p1[1]);
	close(p2[0]);
	close(p2[1]);
	TEST_DONE();

	TEST_START("stdio_fwd dup tcp socket");
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_INT_NE(lfd, -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;
	ASSERT_INT_EQ(bind(lfd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	ASSERT_INT_EQ(listen(lfd, 1), 0);
	sinlen = sizeof(sin);
	ASSERT_INT_EQ(getsockname(lfd, (struct sockaddr *)&sin, &sinlen), 0);

	s1 = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_INT_NE(s1, -1);
	ASSERT_INT_EQ(connect(s1, (struct sockaddr *)&sin, sizeof(sin)), 0);
	s2 = accept(lfd, NULL, NULL);
	ASSERT_INT_NE(s2, -1);
	close(lfd);

	/* Verify opposite ends are NOT collapsed */
	in = dup(s1);
	out = dup(s2);
	ASSERT_INT_NE(in, -1);
	ASSERT_INT_NE(out, -1);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, in, out,
	    CHANNEL_NONBLOCK_SET);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, -1);
	ASSERT_INT_EQ(c->rfd, in);
	ASSERT_INT_EQ(c->wfd, out);
	ASSERT_INT_EQ(c->force_drain, 1);
	channel_free(ssh, c);

	/* Verify duplicate descriptors ARE collapsed */
	ASSERT_INT_EQ(unset_nonblock(s1), 0);
	ASSERT_INT_EQ(set_nonblock(s2), 0);
	in = dup(s1);
	out = dup(s1);
	ASSERT_INT_NE(in, -1);
	ASSERT_INT_NE(out, -1);
	c = channel_connect_stdio_fwd(ssh, "127.0.0.1", 22, in, out,
	    CHANNEL_NONBLOCK_STDIO);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_INT_EQ(c->sock, in);
	ASSERT_INT_EQ(c->rfd, in);
	ASSERT_INT_EQ(c->wfd, in);
	ASSERT_INT_EQ(fcntl(out, F_GETFL), -1);
	ASSERT_INT_EQ(errno, EBADF);
	ASSERT_INT_EQ(c->force_drain, 0);
	ASSERT_INT_EQ(c->restore_block, CHANNEL_RESTORE_RFD);
#ifndef HAVE_CYGWIN
	ASSERT_INT_NE(fcntl(s1, F_GETFL) & O_NONBLOCK, 0);
#endif

	/* Half-close */
	chan_rcvd_ieof(ssh, c);
	pfd.fd = s2;
	pfd.events = POLLIN;
	ASSERT_INT_GE(poll(&pfd, 1, 1000), 1);
	ASSERT_SSIZE_T_EQ(read(s2, &ch, 1), 0);

	channel_free(ssh, c);
#ifndef HAVE_CYGWIN
	ASSERT_INT_EQ(fcntl(s1, F_GETFL) & O_NONBLOCK, 0);
#endif
	close(s1);
	close(s2);
	TEST_DONE();

	channel_free_channels(ssh);
	free(ssh->chanctxt);
	ssh->chanctxt = NULL;
	ssh_packet_free(ssh);
}

void
test_misc(void)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_path_absolute();
	test_stringlist();
	test_skip_space();
	test_stdio_fwd_socket();
}
