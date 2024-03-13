// SPDX-FileCopyrightText: (C) Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/


#include "masqmail.h"

#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>

masqmail_conf conf;


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
	GList *addr_list = NULL, *node;

	conf.debug_level = -1;  /* no debug messages */

	if (argc != 2) {
		fprintf(stderr, "usage: resolvtest HOSTNAME\n");
		return 1;
	}

	if (res_init() != 0) {
		printf("res_init() failed.\n");
		return 1;
	}

	addr_list = resolve_dns_mx(argv[1]);
	foreach(addr_list, node) {
		mxip_addr *p_mxip = (mxip_addr *) (node->data);
		printf("%s  \t%s  %d\n", p_mxip->name,
		       inet_ntoa(*(struct in_addr *) &(p_mxip->ip)), p_mxip->pref);
	}

	return 0;
}
