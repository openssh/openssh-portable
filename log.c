/*

Shared versions of debug(), log(), etc.

*/

#include "includes.h"
RCSID("$OpenBSD: log.c,v 1.1 1999/11/10 23:36:44 markus Exp $");

#include "ssh.h"
#include "xmalloc.h"

/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  fatal_cleanup();
}

/* Error messages that should be logged. */

void
error(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_ERROR, fmt, args);
  va_end(args);
}

/* Log this message (information that usually should go to the log). */

void
log(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_INFO, fmt, args);
  va_end(args);
}

/* More detailed messages (information that does not need to go to the log). */

void
chat(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_CHAT, fmt, args);
  va_end(args);
}

/* Debugging messages that should not be logged during normal operation. */

void
debug(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_DEBUG, fmt, args);
  va_end(args);
}

/* Fatal cleanup */

struct fatal_cleanup
{
  struct fatal_cleanup *next;
  void (*proc)(void *);
  void *context;
};

static struct fatal_cleanup *fatal_cleanups = NULL;

/* Registers a cleanup function to be called by fatal() before exiting. */

void
fatal_add_cleanup(void (*proc)(void *), void *context)
{
  struct fatal_cleanup *cu;

  cu = xmalloc(sizeof(*cu));
  cu->proc = proc;
  cu->context = context;
  cu->next = fatal_cleanups;
  fatal_cleanups = cu;
}

/* Removes a cleanup frunction to be called at fatal(). */

void
fatal_remove_cleanup(void (*proc)(void *context), void *context)
{
  struct fatal_cleanup **cup, *cu;
  
  for (cup = &fatal_cleanups; *cup; cup = &cu->next)
    {
      cu = *cup;
      if (cu->proc == proc && cu->context == context)
	{
	  *cup = cu->next;
	  xfree(cu);
	  return;
	}
    }
  fatal("fatal_remove_cleanup: no such cleanup function: 0x%lx 0x%lx\n",
	(unsigned long)proc, (unsigned long)context);
}

/* Cleanup and exit */
void
fatal_cleanup(void)
{
  struct fatal_cleanup *cu, *next_cu;
  static int called = 0;
  if (called)
    exit(255);
  called = 1;

  /* Call cleanup functions. */
  for (cu = fatal_cleanups; cu; cu = next_cu)
    {
      next_cu = cu->next;
      debug("Calling cleanup 0x%lx(0x%lx)",
	    (unsigned long)cu->proc, (unsigned long)cu->context);
      (*cu->proc)(cu->context);
    }

  exit(255);
}
