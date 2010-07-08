/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

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


gchar*
mserver_detect_online(interface * iface)
{
	struct sockaddr_in saddr;
	gchar *ret = NULL;

	if (init_sockaddr(&saddr, iface)) {
		int sock = socket(PF_INET, SOCK_STREAM, 0);
		int dup_sock;
		if (connect(sock, (struct sockaddr *) (&saddr), sizeof(saddr)) == 0) {
			FILE *in, *out;
			char buf[256];

			dup_sock = dup(sock);
			out = fdopen(sock, "w");
			in = fdopen(dup_sock, "r");

			if (read_sockline(in, buf, 256, 15, READSOCKL_CHUG)) {
				if (strncmp(buf, "READY", 5) == 0) {
					fprintf(out, "STAT\n");
					fflush(out);
					if (read_sockline(in, buf, 256, 15, READSOCKL_CHUG)) {
						if (strncmp(buf, "DOWN", 4) == 0) {
							ret = NULL;
						} else if (strncmp(buf, "UP", 2) == 0) {
							gchar *p = buf + 3;
							while ((*p != ':') && *p)
								p++;
							if (*p) {
								*p = 0;
								p++;
								if ((atoi(p) >= 0) && *p)
									ret = g_strdup(buf + 3);
							} else
								logwrite(LOG_ALERT, "unexpected response from mserver after STAT cmd: %s", buf);
						} else {
							logwrite(LOG_ALERT, "unexpected response from mserver after STAT cmd: %s", buf);
						}
					}
				}
				fprintf(out, "QUIT");
				fflush(out);

				close(sock);
				close(dup_sock);
				fclose(in);
				fclose(out);
			}
		}
	}
	return ret;
}


void
logwrite(int pri, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(stdout, fmt, args);

	va_end(args);
}

void
debugf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(stdout, fmt, args);

	va_end(args);
}

int
main(int argc, char *argv[])
{
	if (argc == 3) {
		interface iface;
		gchar *name;

		iface.address = g_strdup(argv[1]);
		iface.port = atoi(argv[2]);

		name = mserver_detect_online(&iface);

		printf("%s\n", name);

		exit(EXIT_SUCCESS);
	} else {
		fprintf(stderr, "usage %s <host> <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
}
