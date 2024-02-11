// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  child.c
*/

#include "masqmail.h"

int
child(const char *command)
{
	int pipe[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) == 0) {
		pid_t pid;

		pid = fork();
		if (pid == -1) {
			return -1;

		} else if (pid == 0) {
			/* child */
			char *argv[] = { "/bin/sh", "-c", (char *)command,
					NULL };
			int i, max_fd = sysconf(_SC_OPEN_MAX);

			dup2(pipe[0], 0);
			dup2(pipe[0], 1);
			dup2(pipe[0], 2);

			if (max_fd <= 0) {
				max_fd = 64;
			}
			for (i = 3; i < max_fd; i++) {
				close(i);
			}
			execve(*argv, argv, NULL);
			logwrite(LOG_ALERT, "execve failed: %s\n",
					strerror(errno));
			_exit(1);

		} else {
			/* parent */
			close(pipe[0]);
			return pipe[1];
		}
	}
	return -2;
}
