/* Simulator for the moxie processor
   Copyright (C) 2008-2013 Free Software Foundation, Inc.
   Contributed by Anthony Green
   Modified by Krister Lagerström

This file was copied from GDB, the GNU debugger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#define _XOPEN_SOURCE 
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>


/*! Data structure to represent the connection to the xterm */
struct fd_channel
{
  int fdin;
  int fdout;
};

struct xterm_channel
{
  struct fd_channel fds;
  int pid;
  char **argv;
};

static struct xterm_channel *xt_fd = NULL;

/* Forward declaration of static functions */
static void *xterm_init (const char *input);
static int   xterm_open (void *data);
static void  xterm_close (void *data);
static void xterm_exit (int i, void *data);


void xterm_putc (char c)
{
  if (!xt_fd) {
    xt_fd = xterm_init("");
  
    if (xterm_open(xt_fd) == -1) {
      printf("Failed to open xterm\n");
      exit(1);
    }
  }

  write(xt_fd->fds.fdout, &c, 1);

}

int xterm_getc (int peek)
{
  if (!xt_fd) {
    xt_fd = xterm_init("");
  
    if (xterm_open(xt_fd) == -1) {
      printf("Failed to open xterm\n");
      exit(1);
    }
  }
  
  struct pollfd pollfds[1];

  pollfds[0].fd = xt_fd->fds.fdin;
  pollfds[0].events = POLLIN;

  int active_fds = poll(pollfds, 1, 0);
  if ( active_fds < 0 ) {
    perror( "poll" );
    exit(1);
  }

  if (active_fds  == 0) {
    return -1;
  }
    
  //printf("got xterm rx\n");

  if (pollfds[0].revents & POLLIN) {
    if (!peek) {
      char c;

      ssize_t bytes_read = read(pollfds[0].fd, &c, 1);
      if (bytes_read == 0) { /* EOF */
	printf("xterm read error\n");
	exit(1);
      } else if (bytes_read < 0) {
	perror( "read" );
	printf("xterm read error\n");
	exit(1);
      }
      return c;
    } else {
      return 0;
    }    
  } else if ((pollfds[0].revents)
	     & (POLLERR | POLLHUP | POLLNVAL) ) {
    printf("xterm poll error\n");
    exit(1);
  }

  return -1;
}



#define MAX_XTERM_ARGS 100
static void *
xterm_init (const char *input)
{
  struct xterm_channel *retval = malloc (sizeof (struct xterm_channel));

  if (retval)
    {
      int i;
      char *arglist;

      retval->fds.fdin = -1;
      retval->fds.fdout = -1;
      retval->pid = -1;

      /* reset cause exit(1), leaving an xterm opened */
      on_exit (xterm_exit, retval);

      i = 2;
      arglist = (char *) input;
      retval->argv = malloc (sizeof (char *) * MAX_XTERM_ARGS);
      if (!retval->argv)
	{
	  free (retval);
	  return NULL;
	}
      /* Assume xterm arguments are separated by whitespace */
      while ((retval->argv[i++] = strtok (arglist, " \t\n")))
	{
	  arglist = NULL;
	  if (i == MAX_XTERM_ARGS - 1)
	    {
	      free (retval);
	      return NULL;
	    }
	}

    }
  return (void *) retval;
}



static int
xterm_open (void *data)
{
  struct xterm_channel *xt = data;
  int master, retval;
  char *slavename;
  struct termios termio;
  char arg[64], *fin;

  if (!data)
    {
      errno = ENODEV;
      return -1;
    }

  master = open ("/dev/ptmx", O_RDWR);

  if (master < 0)
    return -1;

  grantpt (master);
  unlockpt (master);
  slavename = (char *) ptsname (master);

  if (!slavename)
    {
      errno = ENOTTY;
      goto closemastererror;
    }

  xt->fds.fdout = xt->fds.fdin = open (slavename, O_RDWR);
  if (xt->fds.fdout < 0)
    goto closemastererror;

  retval = tcgetattr (xt->fds.fdin, &termio);
  if (retval < 0)
    goto closeslaveerror;

  cfmakeraw (&termio);
  retval = tcsetattr (xt->fds.fdin, TCSADRAIN, &termio);
  if (retval < 0)
    goto closeslaveerror;

  xt->pid = fork ();

  if (xt->pid == -1)
    goto closeslaveerror;

  if (xt->pid == 0)
    {
      /* Ctrl-C on sim still kill the xterm, grrr */
      signal (SIGINT, SIG_IGN);

      fin = slavename + strlen (slavename) - 2;
      if (strchr (fin, '/'))
	{
	  sprintf (arg, "-S%s/%d", basename (slavename), master);
	}
      else
	{
	  sprintf (arg, "-S%c%c%d", fin[0], fin[1], master);
	}
      xt->argv[0] = "xterm";
      xt->argv[1] = arg;
      execvp ("xterm", xt->argv);
      if (write (master, "\n", 1) < 0)	/* Don't ignore result */
	{
	  printf ("ERROR: xterm: write failed\n");
	}
      exit (1);
    }

  do {
    retval = read (xt->fds.fdin, &arg, 1);
    //printf("Xterm initial read = %c\n", arg[0]);
  } while (retval >= 0 && arg[0] != '\n');
  if (retval < 0)
    goto closeslaveerror;

  cfmakeraw (&termio);
  retval = tcsetattr (xt->fds.fdin, TCSADRAIN, &termio);

  if (retval < 0)
    goto closeslaveerror;

  return 0;

closeslaveerror:
  close (xt->fds.fdin);

closemastererror:
  close (master);
  xt->pid = xt->fds.fdin = xt->fds.fdout = -1;
  return -1;

}

static void
xterm_close (void *data)
{
  struct xterm_channel *xt = data;

  if (!xt)
    return;

  if (xt->fds.fdin != -1)
    close (xt->fds.fdin);

  if (xt->pid != -1)
    {
      kill (xt->pid, SIGKILL);
      waitpid (xt->pid, NULL, 0);
    }

  if (xt->argv)
    free (xt->argv);

  xt->fds.fdin = -1;
  xt->fds.fdout = -1;
  xt->pid = -1;
  xt->argv = NULL;

}

static void
xterm_exit (int i, void *data)
{
  xterm_close (data);
}

