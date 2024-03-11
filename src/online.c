// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2008,2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <sys/wait.h>

gchar*
online_query()
{
	gchar *pipe = conf.online_query;
	pid_t pid;
	void (*old_signal) (int);
	int status;
	int stdout_fd;
	FILE *in;
	gchar *name = NULL;

	if (!conf.online_query) {
		return NULL;
	}
	DEBUG(3) debugf("online query `%s'\n", pipe);

	gchar **argv;
	GError *gerr = NULL;
	if (!g_shell_parse_argv(pipe, NULL, &argv, &gerr)) {
		loggerror(LOG_ERR, gerr, "failed to parse online_query command");
		return NULL;
	}

	old_signal = signal(SIGCHLD, SIG_DFL);

	gboolean ok = g_spawn_async_with_pipes(
			NULL /* workdir */, argv, NULL /* env */,
			G_SPAWN_DO_NOT_REAP_CHILD |
					G_SPAWN_STDIN_FROM_DEV_NULL | G_SPAWN_CHILD_INHERITS_STDERR,
			NULL, NULL, /* child setup */
			&pid, NULL /* in */, &stdout_fd, NULL /* err */, &gerr);
	g_strfreev(argv);
	if (!ok) {
		loggerror(LOG_ERR, gerr, "failed to launch online_query command");
		signal(SIGCHLD, old_signal);
		return NULL;
	}

	gchar output[256];
	in = fdopen(stdout_fd, "r");
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
