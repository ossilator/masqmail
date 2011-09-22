/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright (C) 2008, 2010 markus schnalke <meillo@marmaro.de>

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

#include <sys/wait.h>

#include "masqmail.h"
#include "peopen.h"


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
	if (WEXITSTATUS(status) != 0) {
		g_free(name);
		name = NULL;
	}

	signal(SIGCHLD, old_signal);

	return name;
}
