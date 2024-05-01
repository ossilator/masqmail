// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <fcntl.h>
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

static int
open_log(const gchar *name)
{
	mode_t saved_mode = umask(066);
	gchar *filename = g_strdup_printf("%s/%s.log", conf.log_dir, name);
	int logfd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0666);
	if (logfd < 0) {
		fprintf(stderr, "could not open '%s': %s\n", filename, strerror(errno));
		exit(1);
	}
	g_free(filename);
	umask(saved_mode);
	return logfd;
}

#ifdef ENABLE_DEBUG
static FILE *debugfile = NULL;
#endif

void logopen()
{
	if (conf.use_syslog) {
		openlog(PACKAGE, LOG_PID, LOG_MAIL);
	} else {
		int logfd = open_log("masqmail");
		dup2(logfd, 2);
		close(logfd);
	}

#ifdef ENABLE_DEBUG
	if (conf.debug_level > 0) {
		int dbgfd = open_log("debug");
		debugfile = fdopen(dbgfd, "a");
	}
#endif
}

void
logclose()
{
	if (conf.use_syslog)
		closelog();
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
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	gchar buf[24];

	strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);
	fprintf(stderr, "%s [%d] ", buf, getpid());

	vfprintf(stderr, fmt, args);
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

// this works pretty much like perror()
void
logerrno(int pri, const char *fmt, ...)
{
	va_list args;
	int saved_errno = errno;

	va_start(args, fmt);
	gchar *msg = g_strdup_vprintf(fmt, args);
	va_end(args);
	logwrite(pri, "%s: %s\n", msg, strerror(saved_errno));
	g_free(msg);

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

// stdio is generally assumed to be open, and therefore that
// no newly opened fd will be < 3. we rely on this, too.
void
ensure_stdio(void)
{
	int infl = fcntl(0, F_GETFL);
	int outfl = fcntl(1, F_GETFL);
	int errfl = fcntl(2, F_GETFL);
	if (infl >= 0 && outfl >= 0 && errfl >= 0) {
		return;
	}
	int fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		perror("could not open /dev/null");  // might go nowhere
		exit(1);
	}
	if (infl < 0 && fd != 0) {
		dup2(fd, 0);
	}
	if (outfl < 0 && fd != 1) {
		dup2(fd, 1);
	}
	if (errfl < 0 && fd != 2) {
		dup2(fd, 2);
	}
	// no need to close(fd), as it's by necessity < 3.
}

void
null_stdio(void)
{
	close(0);
	if (open("/dev/null", O_RDWR) < 0) {
		logerrno(LOG_ERR, "could not open /dev/null");
		exit(1);
	}
	dup2(0, 1);
	// leave stderr alone - we may be logging to it
}
