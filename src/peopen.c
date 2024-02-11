/*
**  This a snippet I found in sourceforge. I just changed the identing
**  style to my own and deleted the main function. -- oku
**  The functions destroy_argv() and create_argv() were added by oku.
*/

#include "peopen.h"

#include <glib.h>

#include <ctype.h>
#include <sysexits.h>

/*
** static void
** destroy_argv(char **arr)
** {
** 	char *p = arr[0];
** 	int i = 0;
** 
** 	while (p) {
** 		free(p);
** 		p = arr[i++];
** 	}
** 	free(arr);
** }
*/

static char**
create_argv(const char *cmd, int count)
{
	char buf[strlen(cmd) + 1];
	char **arr, *q;
	const char *p;
	int i = 0;

	arr = (char **) g_malloc(sizeof(char *) * count);

	p = cmd;
	while (*p && i < (count - 1)) {
		while (*p && isspace(*p))
			p++;
		q = buf;
		while (*p && !isspace(*p))
			*q++ = *p++;
		*q = '\0';
		arr[i++] = strdup(buf);
		while (*p && isspace(*p))
			p++;
	}
	arr[i] = NULL;

	return arr;
}

FILE*
peidopen(const char *command, const char *type, char *const envp[],
		int *ret_pid, uid_t uid, gid_t gid)
{
	enum { Read, Write } mode;
	int pipe_fd[2];
	pid_t pid;

	if (command == NULL || type == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (strcmp(type, "r")) {
		if (strcmp(type, "w")) {
			errno = EINVAL;
			return NULL;
		} else
			mode = Write;
	} else
		mode = Read;

	if (pipe(pipe_fd) == -1)
		return NULL;

	switch (pid = fork()) {
	case 0:  /* child thread */

		{
			int i, max_fd = sysconf(_SC_OPEN_MAX);

			if (max_fd <= 0)
				max_fd = 64;
			for (i = 0; i < max_fd; i++)
				if ((i != pipe_fd[0]) && (i != pipe_fd[1]))
					close(i);
		}
		if (close(pipe_fd[mode == Read ? 0 : 1]) != -1 &&
			dup2(pipe_fd[mode == Read ? 1 : 0],
				 mode == Read ? STDOUT_FILENO : STDIN_FILENO) != -1) {
			/* char *argv [] = { "/bin/sh", "-c", (char*) command, NULL }; */
			char **argv = create_argv(command, 10);
			int ret;

			if (uid != (uid_t) - 1) {
				if ((ret = seteuid(0)) != 0) {
					exit(EX_NOPERM);
				}
			}
			if (gid != (gid_t) - 1) {
				if ((ret = setgid(gid)) != 0) {
					exit(EX_NOPERM);
				}
			}
			if (uid != (uid_t) - 1) {
				if ((ret = setuid(uid)) != 0) {
					exit(EX_NOPERM);
				}
			}
			execve(*argv, argv, envp);
		}

		_exit(errno);

	default:  /* parent thread */
		*ret_pid = pid;
		close(pipe_fd[mode == Read ? 1 : 0]);
		return fdopen(pipe_fd[mode == Read ? 0 : 1], type);

	case -1:
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		return NULL;
	}
}

FILE*
peopen(const char *command, const char *type, char *const envp[], int *ret_pid)
{
	return peidopen(command, type, envp, ret_pid, -1, -1);
}
