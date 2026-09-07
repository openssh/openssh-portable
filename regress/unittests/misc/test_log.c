/* 	$OpenBSD$ */
/*
 * Regress tests for log.c syslog lifecycle.
 *
 * Placed in the public domain.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifdef syslog
# undef syslog
#endif

#include "../test_helper/test_helper.h"

#include "log.h"

#if !(defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT))

#define MAX_FAKE_SYSLOG_MSGS 16

struct fake_syslog_msg {
	char ident[64];
	int facility;
	int priority;
	char msg[256];
};

static int fake_syslog_is_open;
static char fake_ident[64];
static int fake_facility;
static int fake_openlog_calls;
static int fake_closelog_calls;
static int fake_socket_opens;
static int fake_syslog_calls;
static struct fake_syslog_msg fake_msgs[MAX_FAKE_SYSLOG_MSGS];

static int fake_handler_calls;
static char fake_handler_msg[256];

void
openlog(const char *ident, int option, int facility)
{
	(void)option;

	fake_openlog_calls++;
	if (!fake_syslog_is_open) {
		fake_socket_opens++;
		fake_syslog_is_open = 1;
	}
	strlcpy(fake_ident, ident == NULL ? "" : ident, sizeof(fake_ident));
	fake_facility = facility;
}

void
closelog(void)
{
	fake_closelog_calls++;
	fake_syslog_is_open = 0;
	fake_ident[0] = '\0';
	fake_facility = 0;
}

static void
fake_vsyslog(int priority, const char *fmt, va_list ap)
{
	struct fake_syslog_msg *m;

	ASSERT_INT_EQ(fake_syslog_is_open, 1);
	ASSERT_INT_LT(fake_syslog_calls, MAX_FAKE_SYSLOG_MSGS);
	m = &fake_msgs[fake_syslog_calls++];
	strlcpy(m->ident, fake_ident, sizeof(m->ident));
	m->facility = fake_facility;
	m->priority = priority;
	vsnprintf(m->msg, sizeof(m->msg), fmt, ap);
}

void
syslog(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fake_vsyslog(priority, fmt, ap);
	va_end(ap);
}

void
__syslog_chk(int priority, int flag, const char *fmt, ...)
{
	va_list ap;

	(void)flag;
	va_start(ap, fmt);
	fake_vsyslog(priority, fmt, ap);
	va_end(ap);
}

void
vsyslog(int priority, const char *fmt, va_list ap)
{
	fake_vsyslog(priority, fmt, ap);
}

void
__vsyslog_chk(int priority, int flag, const char *fmt, va_list ap)
{
	(void)flag;
	fake_vsyslog(priority, fmt, ap);
}

static void
fake_reset(void)
{
	fake_syslog_is_open = 0;
	fake_ident[0] = '\0';
	fake_facility = 0;
	fake_openlog_calls = 0;
	fake_closelog_calls = 0;
	fake_socket_opens = 0;
	fake_syslog_calls = 0;
	memset(fake_msgs, 0, sizeof(fake_msgs));
	fake_handler_calls = 0;
	fake_handler_msg[0] = '\0';
}

static void
reset_log_state(void)
{
	log_init("test_misc", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
	fake_reset();
}

static void
fake_log_handler(LogLevel level, int force, const char *msg, void *ctx)
{
	(void)force;
	(void)ctx;

	fake_handler_calls++;
	ASSERT_INT_EQ(level, SYSLOG_LEVEL_INFO);
	strlcpy(fake_handler_msg, msg, sizeof(fake_handler_msg));
}

static void
test_syslog_kept_open_between_messages(void)
{
	TEST_START("syslog kept open between messages");
	reset_log_state();

	log_init("openssh-auth", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);
	ASSERT_INT_EQ(fake_openlog_calls, 1);
	ASSERT_INT_EQ(fake_socket_opens, 1);
	ASSERT_INT_EQ(fake_closelog_calls, 0);

	do_log2(SYSLOG_LEVEL_INFO, "first message");
	do_log2(SYSLOG_LEVEL_ERROR, "second message");

	ASSERT_INT_EQ(fake_syslog_calls, 2);
	ASSERT_INT_EQ(fake_socket_opens, 1);
	ASSERT_INT_EQ(fake_closelog_calls, 0);
	ASSERT_STRING_EQ(fake_msgs[0].ident, "openssh-auth");
	ASSERT_INT_EQ(fake_msgs[0].facility, LOG_AUTH);
	ASSERT_INT_EQ(fake_msgs[0].priority, LOG_INFO);
	ASSERT_STRING_EQ(fake_msgs[0].msg, "first message");
	ASSERT_STRING_EQ(fake_msgs[1].ident, "openssh-auth");
	ASSERT_INT_EQ(fake_msgs[1].facility, LOG_AUTH);
	ASSERT_INT_EQ(fake_msgs[1].priority, LOG_ERR);
	ASSERT_STRING_EQ(fake_msgs[1].msg, "error: second message");

	TEST_DONE();
}

static void
test_log_init_reopens_on_facility_change(void)
{
	TEST_START("log_init reopens on facility change");
	reset_log_state();

	log_init("openssh-auth", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);
	do_log2(SYSLOG_LEVEL_INFO, "auth message");
	log_init("openssh-user", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 0);
	do_log2(SYSLOG_LEVEL_INFO, "user message");

	ASSERT_INT_EQ(fake_closelog_calls, 1);
	ASSERT_INT_EQ(fake_socket_opens, 2);
	ASSERT_INT_EQ(fake_syslog_calls, 2);
	ASSERT_STRING_EQ(fake_msgs[0].ident, "openssh-auth");
	ASSERT_INT_EQ(fake_msgs[0].facility, LOG_AUTH);
	ASSERT_STRING_EQ(fake_msgs[1].ident, "openssh-user");
	ASSERT_INT_EQ(fake_msgs[1].facility, LOG_USER);
	ASSERT_STRING_EQ(fake_msgs[1].msg, "user message");

	TEST_DONE();
}

static void
test_foreign_syslog_use_is_overwritten(void)
{
	TEST_START("foreign syslog use is overwritten");
	reset_log_state();

	log_init("openssh-auth", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);
	do_log2(SYSLOG_LEVEL_INFO, "before foreign");

	openlog("foreign", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "%s", "foreign message");
	closelog();
	do_log2(SYSLOG_LEVEL_INFO, "after foreign");

	ASSERT_INT_EQ(fake_syslog_calls, 3);
	ASSERT_STRING_EQ(fake_msgs[0].ident, "openssh-auth");
	ASSERT_INT_EQ(fake_msgs[0].facility, LOG_AUTH);
	ASSERT_STRING_EQ(fake_msgs[1].ident, "foreign");
	ASSERT_INT_EQ(fake_msgs[1].facility, LOG_DAEMON);
	ASSERT_STRING_EQ(fake_msgs[2].ident, "openssh-auth");
	ASSERT_INT_EQ(fake_msgs[2].facility, LOG_AUTH);
	ASSERT_STRING_EQ(fake_msgs[2].msg, "after foreign");

	TEST_DONE();
}

static void
test_log_handler_bypasses_syslog(void)
{
	TEST_START("log handler bypasses syslog");
	reset_log_state();

	log_init("openssh-auth", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);
	set_log_handler(fake_log_handler, NULL);
	do_log2(SYSLOG_LEVEL_INFO, "handler message");

	ASSERT_INT_EQ(fake_handler_calls, 1);
	ASSERT_STRING_EQ(fake_handler_msg, "handler message");
	ASSERT_INT_EQ(fake_syslog_calls, 0);

	TEST_DONE();
}

void
test_log(void)
{
	test_syslog_kept_open_between_messages();
	test_log_init_reopens_on_facility_change();
	test_foreign_syslog_use_is_overwritten();
	test_log_handler_bypasses_syslog();
	log_init("test_misc", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
}

#else

void
test_log(void)
{
}

#endif
