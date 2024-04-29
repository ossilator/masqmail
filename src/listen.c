// SPDX-FileCopyrightText: (C) 1999,2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <glib-unix.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/types.h>

static void
child_cb(GPid pid, gint status, G_GNUC_UNUSED gpointer user_data)
{
	if (WIFSIGNALED(status)) {
		logwrite(LOG_WARNING, "process %d got signal: %d\n",
		         pid, WTERMSIG(status));
	} else if (WEXITSTATUS(status) != 0) {
		logwrite(LOG_WARNING, "process %d exited with %d\n",
		         pid, WEXITSTATUS(status));
	}
}

static void
accept_connect(int listen_sock, int sock, struct sockaddr_in *sock_addr)
{
	pid_t pid;
	int dup_sock = dup(sock);
	FILE *out, *in;
	gchar *rem_host;

	rem_host = g_strdup(inet_ntoa(sock_addr->sin_addr));
	logwrite(LOG_INFO, "connect from host %s, port %hu\n",
			rem_host, ntohs(sock_addr->sin_port));

	/* start child for connection: */
	pid = fork();
	if (pid < 0) {
		logerrno(LOG_ERR, "could not fork for incoming smtp connection");
	} else if (pid == 0) {
		/* child */
		close(listen_sock);
		out = fdopen(sock, "w");
		in = fdopen(dup_sock, "r");
		smtp_in(in, out, rem_host);
		_exit(0);
	} else {
		g_child_watch_add(pid, child_cb, NULL);
	}

	g_free(rem_host);
	close(sock);
	close(dup_sock);
}

static gboolean
listen_cb(gint sock, G_GNUC_UNUSED GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{
	struct sockaddr_in clientname;
	socklen_t size = sizeof(clientname);

	int new = accept(sock, (struct sockaddr *) &clientname, &size);
	if (new < 0) {
		logerrno(LOG_ERR, "accept()");
	} else {
		accept_connect(sock, new, &clientname);
	}
	return TRUE;
}

static gboolean
queue_cb(G_GNUC_UNUSED gpointer user_data)
{
	pid_t pid = fork();
	if (pid < 0) {
		logerrno(LOG_ERR, "could not fork for queue run");
	} else if (pid == 0) {
		queue_run();
		_exit(0);
	} else {
		g_child_watch_add(pid, child_cb, NULL);
	}
	return TRUE;
}

void
listen_port(GList *iface_list, gint qival)
{
	/* Create the sockets and set them up to accept connections. */
	foreach_mut (interface *iface, node, iface_list) {
		int sock;

		if ((sock = make_server_socket(iface)) < 0) {
			iface_list = g_list_delete_link(iface_list, node);
			continue;
		}
		if (listen(sock, 1) < 0) {
			logerrno(LOG_ERR, "listen() (terminating)");
			exit(1);
		}
		logwrite(LOG_INFO, "listening on interface %s:%d\n",
				iface->address, iface->port);
		DEBUG(5) debugf("sock = %d\n", sock);
		g_unix_fd_add(sock, G_IO_IN, listen_cb, NULL);
	}

	if (qival > 0) {
		g_timeout_add_seconds(qival, queue_cb, NULL);
	}
}
