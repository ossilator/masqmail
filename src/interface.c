// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static gboolean
init_sockaddr(struct sockaddr_in *name, interface *iface)
{
	struct hostent *he;
	struct in_addr ia;

	if (inet_aton(iface->address, &ia) != 0) {
		/* IP address */
		memcpy(&(name->sin_addr), &ia, sizeof(name->sin_addr));
	} else {
		if ((he = gethostbyname(iface->address)) == NULL) {
			logwrite(LOG_ALERT, "local address '%s' unknown. "
					"(deleting)\n", iface->address);
			return FALSE;
		}
		memcpy(&(name->sin_addr), he->h_addr, sizeof(name->sin_addr));
	}
	name->sin_family = AF_INET;
	name->sin_port = htons(iface->port);

	return TRUE;
}

int
make_server_socket(interface *iface)
{
	int sock = -1;
	struct sockaddr_in server;

	memset(&server, 0, sizeof(struct sockaddr_in));

	/* Create the socket. */
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		logwrite(LOG_ALERT, "socket: %s\n", strerror(errno));
		return -1;
	}

	if (init_sockaddr(&server, iface)) {
		/* bind the socket */
		if (bind(sock, (struct sockaddr *) &server,
				sizeof(server)) < 0) {
			logwrite(LOG_ALERT, "bind: %s\n", strerror(errno));
			return -1;
		}
	} else {
		close(sock);
		return -1;
	}

	return sock;
}
