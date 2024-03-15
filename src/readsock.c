// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "readsock.h"

#include <glib.h>

#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>

static jmp_buf jmp_timeout;

static void
sig_timeout_handler(G_GNUC_UNUSED int sig)
{
	longjmp(jmp_timeout, 1);
}

static struct sigaction old_sa_alrm;

static void
alarm_on(int timeout)
{
	struct sigaction sa;

	sa.sa_handler = sig_timeout_handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, &old_sa_alrm);

	if (timeout > 0)
		alarm(timeout);
}

static void
alarm_off(void)
{
	alarm(0);

	sigaction(SIGALRM, &old_sa_alrm, NULL);
}

static void
_read_chug(FILE *in)
{
	int c = 0;

	c = fgetc(in);
	while (isspace(c) && (c != EOF))
		c = fgetc(in);
	ungetc(c, in);
}

static int
_read_line(FILE *in, char *buf, int buf_len)
{
	int p = 0;
	int c = 0;

	c = fgetc(in);
	while ((c != '\n') && (c != EOF) && (p < buf_len - 1)) {
		buf[p++] = c;
		c = fgetc(in);
	}

	buf[p] = '\0';

	if (c == EOF)
		return -1;
	else if (p >= buf_len) {
		ungetc(c, in);
		return -2;
	}

	buf[p++] = c;  /* \n */
	buf[p] = '\0';

	return p;
}

int
read_sockline(FILE *in, char *buf, int buf_len, int timeout, unsigned int flags)
{
	int p = 0;

	if (setjmp(jmp_timeout) != 0) {
		alarm_off();
		return -3;
	}

	alarm_on(timeout);

	/* strip leading spaces */
	if (flags & READSOCKL_CHUG) {
		_read_chug(in);
	}

	p = _read_line(in, buf, buf_len);

	alarm_off();

	if (p > 1) {
		/* here we are sure that buf[p-1] == '\n' */
		if (flags & READSOCKL_CVT_CRLF) {
			if ((buf[p - 2] == '\r') && (buf[p - 1] == '\n')) {
				buf[p - 2] = '\n';
				buf[p - 1] = 0;
				p--;
			}
		}
	}
	return p;
}

int
read_sockline1(FILE *in, char **pbuf, int *buf_len, int timeout,
		unsigned int flags)
{
	if (setjmp(jmp_timeout) != 0) {
		alarm_off();
		return -3;
	}

	alarm_on(timeout);

	/* strip leading spaces */
	if (flags & READSOCKL_CHUG) {
		_read_chug(in);
	}

	int size = *buf_len;
	if (!*pbuf) {
		*pbuf = (char *) malloc(size);
		if (!*pbuf) {
			fprintf(stderr, "Out of memory.\n");
			exit(1);
		}
	}
	char *buf = *pbuf;

	int p = 0;
	while (1) {
		int pp;

		pp = _read_line(in, buf, size);
		if (pp == -2) {
			*pbuf = realloc(*pbuf, *buf_len + size);
			buf = *pbuf + *buf_len;
			*buf_len += size;
			p += size;
		} else {
			if (pp > 0)
				p += pp;
			else
				p = pp;
			break;
		}
	}

	alarm_off();

	if (p > 1) {
		buf = *pbuf;
		/* here we are sure that buf[p-1] == '\n' */
		if (flags & READSOCKL_CVT_CRLF) {
			if ((buf[p - 2] == '\r') && (buf[p - 1] == '\n')) {
				buf[p - 2] = '\n';
				buf[p - 1] = '\0';
				p--;
			}
		}
	}
	return p;
}
