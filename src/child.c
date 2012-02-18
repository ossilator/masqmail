/*
**  child.c
**  Copyright (C) 2000 by Oliver Kurth,
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <string.h>

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
			int i, max_fd = sysconf(_SC_OPEN_MAX);
			dup2(pipe[0], 0);
			dup2(pipe[0], 1);
			dup2(pipe[0], 2);

			if (max_fd <= 0)
				max_fd = 64;
			for (i = 3; i < max_fd; i++)
				close(i);

			{
				char *argv[] = { "/bin/sh", "-c",
						(char *) command, NULL };
				execve(*argv, argv, NULL);
			}
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
