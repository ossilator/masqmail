// SPDX-FileCopyrightText: (C) 1999,2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/types.h>

static void
sigchld_handler(G_GNUC_UNUSED int sig)
{
	pid_t pid;
	int status;

	pid = waitpid(0, &status, 0);
	if (pid > 0) {
		if (WEXITSTATUS(status) != 0) {
			logwrite(LOG_WARNING, "process %d exited with %d\n",
					pid, WEXITSTATUS(status));
		}
		if (WIFSIGNALED(status)) {
			logwrite(LOG_WARNING, "process %d got signal: %d\n",
					pid, WTERMSIG(status));
		}
	}
	signal(SIGCHLD, sigchld_handler);
}

static void
accept_connect(int listen_sock, int sock, struct sockaddr_in *sock_addr)
{
	pid_t pid;
	int dup_sock = dup(sock);
	FILE *out, *in;
	gchar *rem_host;

	rem_host = g_strdup(inet_ntoa(sock_addr->sin_addr));
	logwrite(LOG_NOTICE, "connect from host %s, port %hu\n",
			rem_host, ntohs(sock_addr->sin_port));

	/* start child for connection: */
	signal(SIGCHLD, sigchld_handler);
	pid = fork();
	if (pid < 0) {
		logwrite(LOG_WARNING, "could not fork for incoming smtp "
				"connection: %s\n", strerror(errno));
	} else if (pid == 0) {
		/* child */
		close(listen_sock);
		out = fdopen(sock, "w");
		in = fdopen(dup_sock, "r");
		smtp_in(in, out, rem_host);
		_exit(0);
	}

	close(sock);
	close(dup_sock);
}

void
listen_port(GList *iface_list, gint qival)
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
			logwrite(LOG_ALERT, "listen: (terminating): %s\n",
					strerror(errno));
			exit(1);
		}
		logwrite(LOG_NOTICE, "listening on interface %s:%d\n",
				iface->address, iface->port);
		DEBUG(5) debugf("sock = %d\n", sock);
		FD_SET(sock, &active_fd_set);
	}

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

		/*
		**  if we were interrupted by an incoming connection (or a
		**  signal) we have to recalculate the time until the next
		**  queue run should occur. select may put a value into tm,
		**  but doc for select() says we should not use it.
		*/
		if (qival > 0) {
			time(&time_now);
			if (!sel_ret) {
				/* either just starting or after a queue run */
				tm.tv_sec = qival;
				tm.tv_usec = 0;
				time_before = time_now;
			} else {
				tm.tv_sec = qival - (time_now - time_before);
				tm.tv_usec = 0;

				/* race condition, unlikely (but possible): */
				if (tm.tv_sec < 0) {
					tm.tv_sec = 0;
				}
			}
		}
		/*
		**  Block until input arrives on one or more active sockets,
		**  or signal arrives, or queuing interval time elapsed
		**  (if qival > 0)
		*/
		read_fd_set = active_fd_set;
		if ((sel_ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL,
				qival > 0 ? &tm : NULL)) < 0) {
			if (errno != EINTR) {
				logwrite(LOG_ALERT, "select: (terminating): "
						"%s\n", strerror(errno));
				exit(1);
			}
		} else if (sel_ret > 0) {
			for (i = 0; i < FD_SETSIZE; i++) {
				int sock = i;
				int new;

				if (!FD_ISSET(i, &read_fd_set)) {
					continue;
				}
				size = sizeof(clientname);
				new = accept(sock, (struct sockaddr *)
						&clientname,
						(socklen_t *)&size);
				if (new < 0) {
					logwrite(LOG_ALERT, "accept: (ignoring): %s\n", strerror(errno));
				} else {
					accept_connect(sock, new,
							&clientname);
				}
			}
		} else {
			/*
			**  If select returns 0, the interval time has elapsed.
			**  We start a new queue runner process
			*/
			int pid;
			signal(SIGCHLD, sigchld_handler);
			if ((pid = fork()) == 0) {
				queue_run();

				_exit(0);
			} else if (pid < 0) {
				logwrite(LOG_ALERT, "could not fork for "
						"queue run");
			}
		}
	}
}
