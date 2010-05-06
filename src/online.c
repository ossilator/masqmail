/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright 2008 markus schnalke <meillo@marmaro.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <sys/stat.h>
#include <sys/wait.h>

#include "masqmail.h"
#include "mserver.h"
#include "peopen.h"

gchar *connection_name;

void
set_online_name(gchar * name)
{
	connection_name = g_strdup(name);
}

static gchar*
detect_online_pipe(const gchar * pipe)
{
	pid_t pid;
	void (*old_signal) (int);
	int status;
	FILE *in;
	gchar *name = NULL;

	old_signal = signal(SIGCHLD, SIG_DFL);

	in = peopen(pipe, "r", environ, &pid);
	if (in == NULL) {
		logwrite(LOG_ALERT, "could not open pipe '%s': %s\n", pipe, strerror(errno));
		signal(SIGCHLD, old_signal);
		return NULL;
	}

	gchar output[256];
	if (fgets(output, 255, in)) {
		g_strchomp(g_strchug(output));
		if (strlen(output) == 0) {
			logwrite(LOG_ALERT, "only whitespace connection name\n");
			name = NULL;
		} else {
			name = g_strdup(output);
		}
	} else {
		logwrite(LOG_ALERT, "nothing read from pipe %s\n", pipe);
		name = NULL;
	}
	fclose(in);
	waitpid(pid, &status, 0);
	if (WEXITSTATUS(status) != EXIT_SUCCESS) {
		g_free(name);
		name = NULL;
	}

	signal(SIGCHLD, old_signal);

	return name;
}

gchar*
detect_online()
{
	if (conf.online_detect == NULL) {
		return NULL;
	}

	if (strcmp(conf.online_detect, "file") == 0) {
		DEBUG(3) debugf("online detection method 'file'\n");
		if (conf.online_file != NULL) {
			logwrite(LOG_ALERT, "online detection mode is 'file', but online_file is undefined\n");
			return NULL;
		}

		struct stat st;
		if (stat(conf.online_file, &st) == 0) {
			FILE *fptr = fopen(conf.online_file, "r");
			if (!fptr) {
				logwrite(LOG_ALERT, "opening of %s failed: %s\n", conf.online_file, strerror(errno));
				return NULL;
			}
			char buf[256];
			if (fgets(buf, 256, fptr) == NULL) {
				logwrite(LOG_ALERT, "empty online file %s\n", conf.online_file);
				fclose(fptr);
				return NULL;
			}
			g_strchomp(g_strchug(buf));
			fclose(fptr);
			if (strlen(buf) == 0) {
				logwrite(LOG_ALERT, "only whitespace connection name in %s\n", conf.online_file);
				return NULL;
			}
			return g_strdup(buf);
		} else if (errno == ENOENT) {
			logwrite(LOG_NOTICE, "not online.\n");
			return NULL;
		} else {
			logwrite(LOG_ALERT, "stat of %s failed: %s", conf.online_file, strerror(errno));
			return NULL;
		}

#ifdef ENABLE_MSERVER
	} else if (strcmp(conf.online_detect, "mserver") == 0) {
		DEBUG(3) debugf("connection method 'mserver'\n");
		return mserver_detect_online(conf.mserver_iface);
#endif
	} else if (strcmp(conf.online_detect, "pipe") == 0) {
		DEBUG(3) debugf("connection method 'pipe'\n");
		if (conf.online_pipe)
			return detect_online_pipe(conf.online_pipe);
		else {
			logwrite(LOG_ALERT, "online detection mode is 'pipe', but online_pipe is undefined\n");
			return NULL;
		}
	} else if (strcmp(conf.online_detect, "argument") == 0) {
		return connection_name;
	} else {
		DEBUG(3) debugf("no connection method selected\n");
	}

	return NULL;
}
