/*  MasqMail
    Copyright (C) 1999 Oliver Kurth

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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "masqmail.h"
#include "smtp_out.h"

masqmail_conf conf;

extern char *optarg;
extern int optind, opterr, optopt;

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
	gchar *helo_name = g_malloc(64);
	gchar *server_name = g_strdup("localhost");
	gint server_port = 25;
	GList *resolve_list = g_list_append(NULL, resolve_byname);

	gethostname(helo_name, 63);

	conf.host_name = g_strdup(helo_name);

	while (1) {
		int c;
		c = getopt(argc, argv, "d:p:s:H:");
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			conf.debug_level = atoi(optarg);
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 's':
			g_free(server_name);
			server_name = g_strdup(optarg);
			break;
		case 'H':
			g_free(helo_name);
			helo_name = g_strdup(optarg);
			break;
		default:
			break;
		}
	}

	if (optind < argc) {
		gint ret;
		message *msg = create_message();

		while (optind < argc) {
			msg->rcpt_list = g_list_append(msg->rcpt_list, create_address_qualified(argv[optind++], TRUE, conf.host_name));
		}

		if ((ret = accept_message(stdin, msg, ACC_NODOT_TERM)) == AERR_OK) {
			if ((ret = smtp_deliver(server_name, server_port, resolve_list, msg, NULL, NULL)) == smtp_ok) {
				exit(EXIT_SUCCESS);
			}
			fprintf(stderr, "deliver failed: %d\n", ret);
		}
		fprintf(stderr, "accept failed: %d\n", ret);
		exit(ret);
	} else {
		fprintf(stderr, "no recipients given.\n");
		exit(-1);
	}
}
