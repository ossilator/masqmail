// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

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

static FILE *logfile = NULL;
#ifdef ENABLE_DEBUG
static FILE *debugfile = NULL;
#endif

gboolean
logopen()
{
	gchar *filename;
	mode_t saved_mode = umask(066);

	if (conf.use_syslog) {
		openlog(PACKAGE, LOG_PID, LOG_MAIL);
	} else {
		uid_t saved_uid;
		gid_t saved_gid;

		if (!conf.run_as_user) {
			set_euidgid(conf.mail_uid, conf.mail_gid, &saved_uid, &saved_gid);
		}

		filename = g_strdup_printf("%s/masqmail.log", conf.log_dir);
		logfile = fopen(filename, "a");
		if (!logfile) {
			fprintf(stderr, "could not open log '%s': %s\n", filename, strerror(errno));
			if (!conf.run_as_user) {
				set_euidgid(saved_uid, saved_gid, NULL, NULL);
			}
			return FALSE;
		}
		g_free(filename);

		if (!conf.run_as_user) {
			set_euidgid(saved_uid, saved_gid, NULL, NULL);
		}
	}

#ifdef ENABLE_DEBUG
	if (conf.debug_level > 0) {
		filename = g_strdup_printf("%s/debug.log", conf.log_dir);
		debugfile = fopen(filename, "a");
		if (!debugfile) {
			fprintf(stderr, "could not open debug log '%s'\n", filename);
			return FALSE;
		}
		g_free(filename);
	}
#endif
	umask(saved_mode);
	return TRUE;
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

static void
vlogwrite(int pri, const char *fmt, va_list args)
{
	if (conf.use_syslog) {
		vsyslog(pri, fmt, args);
		return;
	}
	FILE *file = logfile ? logfile : stderr;
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	gchar buf[24];

	strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);
	fprintf(file, "%s [%d] ", buf, getpid());

	vfprintf(file, fmt, args);
	fflush(file);
}

#ifdef ENABLE_DEBUG
static void
vdebugwrite(int pri, const char *fmt, va_list args)
{
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	gchar buf[24];
	strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);

	if (debugfile) {
		fprintf(debugfile, "%s [%d] ", buf, getpid());
		vfprintf(debugfile, fmt, args);
		fflush(debugfile);
	} else {
		fprintf(stderr, "no debug file, msg was:\n");
		vfprintf(stderr, fmt, args);
	}
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
	if (debugfile)
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
