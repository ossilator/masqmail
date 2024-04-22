// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2008,2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "peopen.h"

#include <sys/wait.h>

gchar*
online_query()
{
	gchar *pipe = conf.online_query;
	pid_t pid;
	void (*old_signal) (int);
	int status;
	FILE *in;
	gchar *name = NULL;

	if (!conf.online_query) {
		return NULL;
	}
	DEBUG(3) debugf("online query `%s'\n", pipe);

	old_signal = signal(SIGCHLD, SIG_DFL);

	in = peopen(pipe, "r", environ, &pid);
	if (!in) {
		logerrno(LOG_ERR, "could not open pipe '%s'", pipe);
		signal(SIGCHLD, old_signal);
		return NULL;
	}

	gchar output[256];
	if (fgets(output, 255, in)) {
		g_strchomp(g_strchug(output));
		if (strlen(output) == 0) {
			logwrite(LOG_ERR, "only whitespace connection name\n");
			name = NULL;
		} else {
			name = g_strdup(output);
		}
	} else {
		logwrite(LOG_ERR, "nothing read from pipe %s\n", pipe);
		name = NULL;
	}
	fclose(in);
	waitpid(pid, &status, 0);
	if (WEXITSTATUS(status) != 0) {
		g_free(name);
		name = NULL;
	}

	signal(SIGCHLD, old_signal);

	return name;
}
