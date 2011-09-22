/*  MasqMail
    Copyright (C) 2000 Oliver Kurth

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

#include "masqmail.h"

/* define if you get problems... */
/*#define SOCKADDR_OLD 1*/

gboolean
init_sockaddr(struct sockaddr_in *name, interface *iface)
{
	struct hostent *he;
	struct in_addr ia;

#ifdef SOCKADDR_OLD
	/* here I tried to be intelligent and failed. */
	if (isalpha(iface->address[0])) {
		if ((he = gethostbyname(iface->address)) == NULL) {
			logwrite(LOG_ALERT, "local address '%s' unknown. (deleting)\n", iface->address);
			return FALSE;
		}
		memcpy(&(name->sin_addr), he->h_addr, sizeof(name->sin_addr));
	} else if (isdigit(iface->address[0])) {
		if (inet_aton(iface->address, &ia)) {
			memcpy(&(name->sin_addr), &ia, sizeof(name->sin_addr));
		} else {
			logwrite(LOG_ALERT, "invalid address '%s': inet_aton() failed (deleting)\n", iface->address);
			return FALSE;
		}
	} else {
		logwrite(LOG_ALERT, "invalid address '%s', should begin with a aphanumeric (deleting)\n", iface->address);
		return FALSE;
	}
#else
	/* this is how others to it. I follow the crowd... */
	if (inet_aton(iface->address, &ia) != 0) {
		/* IP address */
		memcpy(&(name->sin_addr), &ia, sizeof(name->sin_addr));
	} else {
		if ((he = gethostbyname(iface->address)) == NULL) {
			logwrite(LOG_ALERT, "local address '%s' unknown. (deleting)\n", iface->address);
			return FALSE;
		}
		memcpy(&(name->sin_addr), he->h_addr, sizeof(name->sin_addr));
	}
#endif
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
		if (bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
			logwrite(LOG_ALERT, "bind: %s\n", strerror(errno));
			return -1;
		}
	} else {
		close(sock);
		return -1;
	}

	return sock;
}
