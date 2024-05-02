// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "readsock.h"

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static gboolean
init_sockaddr2(struct sockaddr_in *name, const gchar *addr, int port)
{
	struct hostent *he;
	struct in_addr ia;

	if (inet_aton(addr, &ia) != 0) {
		/* IP address */
		memcpy(&(name->sin_addr), &ia, sizeof(name->sin_addr));
	} else {
		if ((he = gethostbyname(addr)) == NULL) {
			fprintf(stderr, "local address '%s' unknown. (deleting)\n", addr);
			return FALSE;
		}
		memcpy(&(name->sin_addr), he->h_addr, sizeof(name->sin_addr));
	}
	name->sin_family = AF_INET;
	name->sin_port = htons(port);

	return TRUE;
}


static gchar*
mserver_detect_online(const gchar *addr, int port)
{
	struct sockaddr_in saddr;
	gchar *ret = NULL;

	if (!init_sockaddr2(&saddr, addr, port)) {
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

	/*
	**  this is the protocol (reverse engineered):
	**
	**                    S: READY
	**                    C: STAT
	**                        |
	**       +----------------+-----------------+
	**       |                |                 |
	**   S: DOWN          S: UP foo:-1      S: UP foo:1
	**   C: QUIT          C: QUIT           C: QUIT
	**
	**   -> offline       -> offline        -> online
	**                                      `foo' gets printed
	**
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


int
main(int argc, const char * const argv[])
{
	const gchar *addr;
	int port;
	gchar *name;

	if (argc != 3) {
		fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
		return 1;
	}

	addr = argv[1];
	port = atoi(argv[2]);

	name = mserver_detect_online(addr, port);

	if (name) {
		printf("%s\n", name);
		return 0;
	}
	return 1;
}
