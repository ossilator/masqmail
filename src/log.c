// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <assert.h>
#include <sys/stat.h>
#include <sysexits.h>

static char *_sysexit_strings[] = {
	"command line usage error",
	"data format error",
	"cannot open input",
	"addressee unknown",
	"host name unknown",
	"service unavailable",
	"internal software error",
	"system error (e.g., can't fork)",
	"critical OS file missing",
	"can't create (user) output file",
	"input/output error",
	"temp failure; user is invited to retry",
	"remote error in protocol",
	"permission denied",
	"configuration error"
};

gchar*
ext_strerror(int err)
{
	if (err < 1024)
		return strerror(err);
	else if (err > 1024 + EX__BASE
	         && (err - 1024 - EX__BASE < sizeof(_sysexit_strings) / sizeof(_sysexit_strings[0])))
		return _sysexit_strings[err - 1024 - EX__BASE];

	return "unknown error";
}

static gboolean
open_log(const gchar *name, FILE **file)
{
	gboolean ret = TRUE;
	mode_t saved_mode = umask(066);
	gchar *filename = g_strdup_printf("%s/%s.log", conf.log_dir, name);
	*file = fopen(filename, "a");
	if (!*file) {
		fprintf(stderr, "could not open '%s': %s\n", filename, strerror(errno));
		ret = FALSE;
	}
	g_free(filename);
	umask(saved_mode);
	return ret;
}

static FILE *logfile = NULL;
#ifdef ENABLE_DEBUG
static FILE *debugfile = NULL;
#endif

gboolean
logopen()
{
#ifdef ENABLE_DEBUG
	if (conf.debug_level && !open_log("debug", &debugfile)) {
		return FALSE;
	}
#endif

	if (conf.use_syslog) {
		openlog(PACKAGE, LOG_PID, LOG_MAIL);
		return TRUE;
	}
	return open_log("masqmail", &logfile);
}

void
logclose()
{
	if (conf.use_syslog)
		closelog();
	else if (logfile)
		fclose(logfile);
#ifdef ENABLE_DEBUG
	if (debugfile)
		fclose(debugfile);
#endif
}

static_assert(LOG_DEBUG == 7, "LOG_DEBUG has unexpected value");
static const char * const log_strings[] = {
	"panic",
	"alert",
	"critical",
	"error",
	"warning",
	"notice",
	"info",
	"debug",
};

void
vlogwrite(int pri, const char *fmt, va_list args)
{
	if (conf.use_syslog) {
		vsyslog(pri, fmt, args);
		return;
	}
	FILE *file = logfile ? logfile : pri <= LOG_WARNING ? stderr : stdout;
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	gchar buf[24];

	strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);
	fprintf(file, "%s [%d] %s: ", buf, getpid(), log_strings[pri]);

	vfprintf(file, fmt, args);
	fflush(file);
}

#ifdef ENABLE_DEBUG
void
vdebugwrite(int pri, const char *fmt, va_list args)
{
	FILE *file = debugfile ? debugfile : stdout;
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	gchar buf[24];
	strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);
	fprintf(file, "%s [%d] %s: ", buf, getpid(), log_strings[pri]);
	vfprintf(file, fmt, args);
	fflush(file);
}
#endif

void
logwrite(int pri, const char *fmt, ...)
{
	va_list args, args_copy;
	int saved_errno = errno;  /* somewhere this is changed to EBADF */

	va_start(args, fmt);
#ifdef ENABLE_DEBUG
	va_copy(args_copy, args);
#endif
	vlogwrite(pri, fmt, args);
#ifdef ENABLE_DEBUG
	if (debugfile || (conf.debug_level && conf.use_syslog))
		vdebugwrite(pri, fmt, args_copy);
	va_end(args_copy);
#endif
	va_end(args);

	errno = saved_errno;
}

#ifdef ENABLE_DEBUG
void
debugf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vdebugwrite(LOG_DEBUG, fmt, args);

	va_end(args);
}

void
vdebugf(const char *fmt, va_list args)
{
	vdebugwrite(LOG_DEBUG, fmt, args);
}
#endif

void
maillog(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vlogwrite(LOG_NOTICE, fmt, args);

	va_end(args);
}
