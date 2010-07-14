/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright (C) 2010 markus schnalke <meillo@marmaro.de>

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


#include "config.h"
#include "masqmail.h"
#include "readsock.h"



gboolean
init_sockaddr(struct sockaddr_in * name, interface * iface)
{
	struct hostent *he;
	struct in_addr ia;

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
	name->sin_family = AF_INET;
	name->sin_port = htons(iface->port);

	return TRUE;
}


int
make_server_socket(interface * iface)
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




gchar*
mserver_detect_online(interface * iface)
{
	struct sockaddr_in saddr;
	gchar *ret = NULL;

	if (!init_sockaddr(&saddr, iface)) {
		return NULL;
	}

	int sock = socket(PF_INET, SOCK_STREAM, 0);
	int dup_sock;
	if (connect(sock, (struct sockaddr *) (&saddr), sizeof(saddr)) != 0) {
		return NULL;
	}

	FILE *in, *out;
	char buf[256];

	dup_sock = dup(sock);
	out = fdopen(sock, "w");
	in = fdopen(dup_sock, "r");

	if (!read_sockline(in, buf, 256, 15, READSOCKL_CHUG)) {
		return NULL;
	}

	/* this is the protocol (reverse engineered):
	   S: READY
	   C: STAT
	   S: DOWN
	   C: QUIT
	   -> offline
	   
	   S: READY
	   C: STAT
	   S: UP foo:-1
	   C: QUIT
	   -> offline
	   
	   S: READY
	   C: STAT
	   S: UP foo:1
	   C: QUIT
	   -> online, `foo' gets printed
	*/

	if (strncmp(buf, "READY", 5) == 0) {
		fprintf(out, "STAT\n");
		fflush(out);
		if (read_sockline(in, buf, 256, 15, READSOCKL_CHUG)) {
			if (strncmp(buf, "DOWN", 4) == 0) {
				ret = NULL;
			} else if (strncmp(buf, "UP", 2) == 0) {
				gchar *p = buf + 3;
				while ((*p != ':') && *p) {
					p++;
				}
				if (*p) {
					*p = '\0';
					p++;
					if ((atoi(p) >= 0) && *p) {
						/* `UP foo:N', where `N' is a non-negative number */
						ret = g_strdup(buf + 3);
					}
				} else {
					fprintf(stderr, "unexpected response from mserver after STAT cmd: %s", buf);
				}
			} else {
				fprintf(stderr, "unexpected response from mserver after STAT cmd: %s", buf);
			}
		}
	}
	fprintf(out, "QUIT");
	fflush(out);

	close(sock);
	close(dup_sock);
	fclose(in);
	fclose(out);

	return ret;
}


void
logwrite(int pri, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(stderr, fmt, args);

	va_end(args);
}


int
main(int argc, char *argv[])
{
	interface iface;
	gchar *name;

	if (argc != 3) {
		fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
		return 1;
	}

	iface.address = g_strdup(argv[1]);
	iface.port = atoi(argv[2]);

	name = mserver_detect_online(&iface);

	if (name) {
		printf("%s\n", name);
		return 0;
	}
	return 1;
}
