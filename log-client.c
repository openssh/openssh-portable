/*

log-client.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:13:40 1995 ylo

Client-side versions of debug(), log(), etc.  These print to stderr.

*/

#include "includes.h"
RCSID("$Id: log-client.c,v 1.1 1999/10/27 03:42:44 damien Exp $");

#include "xmalloc.h"
#include "ssh.h"

static int log_debug = 0;
static int log_quiet = 0;

void log_init(char *av0, int on_stderr, int debug, int quiet,
	      SyslogFacility facility)
{
  log_debug = debug;
  log_quiet = quiet;
}

void log(const char *fmt, ...)
{
  va_list args;

  if (log_quiet)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\r\n");
  va_end(args);
}

void debug(const char *fmt, ...)
{
  va_list args;
  if (log_quiet || !log_debug)
    return;
  va_start(args, fmt);
  fprintf(stderr, "debug: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\r\n");
  va_end(args);
}

void error(const char *fmt, ...)
{
  va_list args;
  if (log_quiet)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\r\n");
  va_end(args);
}

struct fatal_cleanup
{
  struct fatal_cleanup *next;
  void (*proc)(void *);
  void *context;
};

static struct fatal_cleanup *fatal_cleanups = NULL;

/* Registers a cleanup function to be called by fatal() before exiting. */

void fatal_add_cleanup(void (*proc)(void *), void *context)
{
  struct fatal_cleanup *cu;

  cu = xmalloc(sizeof(*cu));
  cu->proc = proc;
  cu->context = context;
  cu->next = fatal_cleanups;
  fatal_cleanups = cu;
}

/* Removes a cleanup frunction to be called at fatal(). */

void fatal_remove_cleanup(void (*proc)(void *context), void *context)
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

/* Function to display an error message and exit.  This is in this file because
   this needs to restore terminal modes before exiting.  See log-client.c
   for other related functions. */

void fatal(const char *fmt, ...)
{
  va_list args;
  struct fatal_cleanup *cu, *next_cu;
  static int fatal_called = 0;
  
  if (!fatal_called)
    {
      fatal_called = 1;

      /* Call cleanup functions. */
      for (cu = fatal_cleanups; cu; cu = next_cu)
	{
	  next_cu = cu->next;
	  (*cu->proc)(cu->context);
	}
    }

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\r\n");
  va_end(args);
  exit(255);
}

/* fatal() is in ssh.c so that it can properly reset terminal modes. */
