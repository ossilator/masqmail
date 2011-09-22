/*  MasqMail
    Copyright (C) 1999/2000 Oliver Kurth

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
#include <sys/types.h>

#include "masqmail.h"

static int volatile sighup_seen = 0;

static void
sighup_handler(int sig)
{
	sighup_seen = 1;
	signal(SIGHUP, sighup_handler);
}

static void
sigchld_handler(int sig)
{
	pid_t pid;
	int status;

	pid = waitpid(0, &status, 0);
	if (pid > 0) {
		if (WEXITSTATUS(status) != 0)
			logwrite(LOG_WARNING, "process %d exited with %d\n", pid, WEXITSTATUS(status));
		if (WIFSIGNALED(status))
			logwrite(LOG_WARNING, "process with pid %d got signal: %d\n", pid, WTERMSIG(status));
	}
	signal(SIGCHLD, sigchld_handler);
}

void
accept_connect(int listen_sock, int sock, struct sockaddr_in *sock_addr)
{
	pid_t pid;
	int dup_sock = dup(sock);
	FILE *out, *in;
	gchar *rem_host;
	gchar *ident = NULL;

	rem_host = g_strdup(inet_ntoa(sock_addr->sin_addr));
#ifdef ENABLE_IDENT
	{
		gchar *id = NULL;
		if ((id = (gchar *) ident_id(sock, 60))) {
			ident = g_strdup(id);
		}
		logwrite(LOG_NOTICE, "connect from host %s, port %hd ident=%s\n", rem_host,
		         ntohs(sock_addr->sin_port), ident ? ident : "(unknown)");
	}
#else
	logwrite(LOG_NOTICE, "connect from host %s, port %hd\n", rem_host, ntohs(sock_addr->sin_port));
#endif

	/* start child for connection: */
	signal(SIGCHLD, sigchld_handler);
	pid = fork();
	if (pid == 0) {
		close(listen_sock);
		out = fdopen(sock, "w");
		in = fdopen(dup_sock, "r");

		smtp_in(in, out, rem_host, ident);

		_exit(0);
	} else if (pid < 0) {
		logwrite(LOG_WARNING, "could not fork for incoming smtp connection: %s\n", strerror(errno));
	}
#ifdef ENABLE_IDENT
	if (ident != NULL)
		g_free(ident);
#endif

	close(sock);
	close(dup_sock);
}

void
listen_port(GList *iface_list, gint qival, char *argv[])
{
	int i;
	fd_set active_fd_set, read_fd_set;
	struct timeval tm;
	time_t time_before, time_now;
	struct sockaddr_in clientname;
	size_t size;
	GList *node, *node_next;
	int sel_ret;

	/* Create the sockets and set them up to accept connections. */
	FD_ZERO(&active_fd_set);
	for (node = g_list_first(iface_list); node; node = node_next) {
		interface *iface = (interface *) (node->data);
		int sock;

		node_next = g_list_next(node);
		if ((sock = make_server_socket(iface)) < 0) {
			iface_list = g_list_remove_link(iface_list, node);
			g_list_free_1(node);
			continue;
		}
		if (listen(sock, 1) < 0) {
			logwrite(LOG_ALERT, "listen: (terminating): %s\n", strerror(errno));
			exit(1);
		}
		logwrite(LOG_NOTICE, "listening on interface %s:%d\n", iface->address, iface->port);
		DEBUG(5) debugf("sock = %d\n", sock);
		FD_SET(sock, &active_fd_set);
	}

	/* setup handler for HUP signal: */
	signal(SIGHUP, sighup_handler);
	signal(SIGCHLD, sigchld_handler);

	/* now that we have our socket(s), we can give up root privileges */
	if (!conf.run_as_user) {
		set_euidgid(conf.mail_uid, conf.mail_gid, NULL, NULL);
	}

	/*  sel_ret = 0; */
	time(&time_before);
	time_before -= qival;
	sel_ret = -1;

	while (1) {

		/* if we were interrupted by an incoming connection (or a signal)
		   we have to recalculate the time until the next queue run should
		   occur. select may put a value into tm, but doc for select() says
		   we should not use it. */
		if (qival > 0) {
			time(&time_now);
			if (sel_ret == 0) {  /* we are either just starting or did a queue run */
				tm.tv_sec = qival;
				tm.tv_usec = 0;
				time_before = time_now;
			} else {
				tm.tv_sec = qival - (time_now - time_before);
				tm.tv_usec = 0;

				/* race condition, very unlikely (but possible): */
				if (tm.tv_sec < 0)
					tm.tv_sec = 0;
			}
		}
		/* Block until input arrives on one or more active sockets,
		   or signal arrives, or queuing interval time elapsed (if qival > 0) */
		read_fd_set = active_fd_set;
		if ((sel_ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL, qival > 0 ? &tm : NULL)) < 0) {
			if (errno != EINTR) {
				logwrite(LOG_ALERT, "select: (terminating): %s\n", strerror(errno));
				exit(1);
			} else {
				if (sighup_seen) {
					logwrite(LOG_NOTICE, "HUP signal received. Restarting daemon\n");

					for (i = 0; i < FD_SETSIZE; i++)
						if (FD_ISSET(i, &active_fd_set))
							close(i);

					execv(argv[0], &(argv[0]));
					logwrite(LOG_ALERT, "restarting failed: %s\n", strerror(errno));
					exit(1);
				}
			}
		} else if (sel_ret > 0) {
			for (i = 0; i < FD_SETSIZE; i++) {
				if (FD_ISSET(i, &read_fd_set)) {
					int sock = i;
					int new;
					size = sizeof(clientname);
					new = accept(sock, (struct sockaddr *) &clientname, &size);
					if (new < 0) {
						logwrite(LOG_ALERT, "accept: (ignoring): %s\n", strerror(errno));
					} else
						accept_connect(sock, new, &clientname);
				}
			}
		} else {
			/* If select returns 0, the interval time has elapsed.
			   We start a new queue runner process */
			int pid;
			signal(SIGCHLD, sigchld_handler);
			if ((pid = fork()) == 0) {
				queue_run();

				_exit(0);
			} else if (pid < 0) {
				logwrite(LOG_ALERT, "could not fork for queue run");
			}
		}
	}
}
